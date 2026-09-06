package msix

import (
	"archive/zip"
	"bufio"
	"compress/flate"
	"crypto/sha256"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

// compressedEntry holds everything needed to (a) emit a ZIP entry via CreateRaw and
// (b) describe the entry in the block map, without keeping the payload in memory.
// For Deflate entries the compressed bytes live in a temp spill file; for Store
// entries the bytes are re-read from the source at write time.
type compressedEntry struct {
	name             string
	method           uint16 // zip.Deflate or zip.Store
	uncompressedSize uint64
	compressedSize   uint64
	crc32            uint32
	lfhSize          uint64
	blocks           []blockEntry
	spillPath        string     // "" for Store entries
	source           fileSource // used to re-read bytes for Store entries
}

// readBlock fills buf from r, returning the number of bytes read. A short final
// block (io.ErrUnexpectedEOF) and a clean end (io.EOF, n==0) are both reported as a
// nil error; only genuine read failures are returned.
func readBlock(r io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(r, buf)
	switch err {
	case nil, io.ErrUnexpectedEOF:
		return n, nil
	case io.EOF:
		return 0, nil
	default:
		return n, err
	}
}

// countWriter counts bytes written through to the underlying writer.
type countWriter struct {
	w io.Writer
	n *uint64
}

func (c countWriter) Write(p []byte) (int, error) {
	m, err := c.w.Write(p)
	*c.n += uint64(m)
	return m, err
}

// compressSourceToSpill reads src once in 64KB blocks. Unless forceStore is set (or
// the source is empty), each block is independently DEFLATE-compressed to a temp
// spill file with the MSIX discipline (intermediate blocks Flush, final block Close),
// recording the per-block SHA256 of the *uncompressed* data and the compressed size.
// Memory use is bounded to ~2 blocks regardless of file size.
func compressSourceToSpill(name string, src fileSource, forceStore bool, tempDir string) (*compressedEntry, error) {
	rc, err := src.open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	first := make([]byte, blockSize)
	firstN, err := readBlock(rc, first)
	if err != nil {
		return nil, err
	}

	if forceStore || firstN == 0 {
		return storeStreaming(name, src, rc, first[:firstN])
	}

	spill, err := os.CreateTemp(tempDir, "msix-cmp-*")
	if err != nil {
		return nil, err
	}
	spillPath := spill.Name()
	fail := func(e error) (*compressedEntry, error) {
		spill.Close()
		os.Remove(spillPath)
		return nil, e
	}

	bw := bufio.NewWriterSize(spill, blockSize)
	crc := crc32.NewIEEE()
	var blocks []blockEntry
	var uncompressed, compressed uint64

	cur, curN := first, firstN
	next := make([]byte, blockSize)
	for {
		nextN, rerr := readBlock(rc, next)
		if rerr != nil {
			return fail(rerr)
		}
		last := nextN == 0

		block := cur[:curN]
		crc.Write(block)
		h := sha256.Sum256(block)

		before := compressed
		fw, _ := flate.NewWriter(countWriter{w: bw, n: &compressed}, flate.DefaultCompression)
		if _, err := fw.Write(block); err != nil {
			return fail(err)
		}
		if last {
			if err := fw.Close(); err != nil {
				return fail(err)
			}
		} else if err := fw.Flush(); err != nil {
			return fail(err)
		}
		blocks = append(blocks, blockEntry{Hash: h, CompressedSize: compressed - before})
		uncompressed += uint64(curN)

		if last {
			break
		}
		cur, next = next, cur
		curN = nextN
	}

	if err := bw.Flush(); err != nil {
		return fail(err)
	}
	if err := spill.Close(); err != nil {
		os.Remove(spillPath)
		return nil, err
	}

	return &compressedEntry{
		name:             name,
		method:           zip.Deflate,
		uncompressedSize: uncompressed,
		compressedSize:   compressed,
		crc32:            crc.Sum32(),
		lfhSize:          computeLfhSize(name),
		blocks:           blocks,
		spillPath:        spillPath,
		source:           src,
	}, nil
}

// storeStreaming builds a Store entry: it computes the CRC32 and per-64KB block
// SHA256 hashes by streaming the source, without compressing or spilling. The bytes
// are re-read from the source when the entry is written.
func storeStreaming(name string, src fileSource, rc io.Reader, first []byte) (*compressedEntry, error) {
	crc := crc32.NewIEEE()
	var blocks []blockEntry
	var total uint64

	process := func(block []byte) {
		crc.Write(block)
		h := sha256.Sum256(block)
		blocks = append(blocks, blockEntry{Hash: h}) // no CompressedSize for Store
		total += uint64(len(block))
	}

	if len(first) == 0 {
		// Empty file: a single block hashing the empty input (matches the
		// original computeBlockHashes/writeFileStore behavior).
		h := sha256.Sum256(nil)
		blocks = append(blocks, blockEntry{Hash: h})
	} else {
		process(first)
		buf := make([]byte, blockSize)
		for {
			n, err := readBlock(rc, buf)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				break
			}
			process(buf[:n])
		}
	}

	return &compressedEntry{
		name:             name,
		method:           zip.Store,
		uncompressedSize: total,
		compressedSize:   total,
		crc32:            crc.Sum32(),
		lfhSize:          computeLfhSize(name),
		blocks:           blocks,
		spillPath:        "",
		source:           src,
	}, nil
}

// zipFileEntry converts the entry into the metadata shape consumed by the block map.
func (e *compressedEntry) zipFileEntry() zipFileEntry {
	return zipFileEntry{
		Name:    e.name,
		Size:    e.uncompressedSize,
		LfhSize: e.lfhSize,
		Blocks:  e.blocks,
	}
}

// computeDigests reproduces the unsigned package byte-for-byte through a discarding
// hash splitter to obtain AXPC (local headers + data) and AXCD (central directory + end records),
// without buffering the package payload. Only the central directory is held in memory.
func computeDigests(unsignedEntries []*compressedEntry) (axpc, axcd [32]byte, err error) {
	// The central directory begins after every local record, where each local record
	// is LFH (30 + name, no extra field) + compressed data.
	var cdOffset int64
	for _, e := range unsignedEntries {
		cdOffset += int64(e.lfhSize) + int64(e.compressedSize)
	}

	s := &digestSplitter{cdOffset: cdOffset, axpc: sha256.New()}
	zw := zip.NewWriter(s)
	for _, e := range unsignedEntries {
		if err := writeEntry(zw, e); err != nil {
			return axpc, axcd, err
		}
	}
	if err := zw.Close(); err != nil {
		return axpc, axcd, err
	}
	copy(axpc[:], s.axpc.Sum(nil))

	axcd = sha256.Sum256(s.tail)
	return axpc, axcd, nil
}

// writeEntry emits one entry into zw via CreateRaw, matching the header layout of the
// original hashingZipWriter exactly, then streams the entry's bytes (compressed spill
// for Deflate, source bytes for Store) into the raw writer.
func writeEntry(zw *zip.Writer, e *compressedEntry) error {
	header := &zip.FileHeader{
		Name:               e.name,
		Method:             e.method,
		CRC32:              e.crc32,
		CompressedSize64:   e.compressedSize,
		UncompressedSize64: e.uncompressedSize,
	}
	if e.compressedSize < 0xFFFFFFFF {
		header.CompressedSize = uint32(e.compressedSize)
	}
	if e.uncompressedSize < 0xFFFFFFFF {
		header.UncompressedSize = uint32(e.uncompressedSize)
	}
	prepareHeader(header)

	w, err := zw.CreateRaw(header)
	if err != nil {
		return err
	}

	var src io.ReadCloser
	if e.spillPath != "" {
		src, err = os.Open(e.spillPath)
	} else {
		src, err = e.source.open()
	}
	if err != nil {
		return err
	}
	defer src.Close()

	_, err = io.Copy(w, src)
	return err
}

// digestSplitter routes the first cdOffset bytes (all local headers + data) into the
// AXPC hash and buffers the remainder (central directory + EOCD trailers) so AXCD can
// include the central directory and its end records. Splitting by absolute byte offset is
// robust to the bufio buffering inside zip.Writer (a flag flipped around Close() is
// not, because Close flushes buffered local-record bytes together with the central
// directory). Only the central directory (∝ file count, not payload size) is buffered.
type digestSplitter struct {
	cdOffset int64
	n        int64
	axpc     hash.Hash
	tail     []byte
}

func (s *digestSplitter) Write(p []byte) (int, error) {
	total := len(p)
	if remaining := s.cdOffset - s.n; remaining > 0 {
		take := int64(len(p))
		if take > remaining {
			take = remaining
		}
		s.axpc.Write(p[:take])
		s.tail = append(s.tail, p[take:]...)
	} else {
		s.tail = append(s.tail, p...)
	}
	s.n += int64(total)
	return total, nil
}
