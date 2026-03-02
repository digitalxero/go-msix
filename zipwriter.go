package msix

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
)

// blockSize is the MSIX block size for independent compression and hashing.
const blockSize = 64 * 1024 // 64 KB

// blockEntry holds the hash and compressed size of a single 64KB block.
type blockEntry struct {
	Hash           [sha256.Size]byte
	CompressedSize uint64
}

// zipFileEntry holds metadata about a file written to the ZIP, used for block map generation.
type zipFileEntry struct {
	Name    string
	Size    uint64
	LfhSize uint64
	Blocks  []blockEntry
}

// hashingZipWriter wraps archive/zip.Writer to write files with independent
// 64KB block compression and track per-file metadata needed for MSIX block maps.
type hashingZipWriter struct {
	zw      *zip.Writer
	entries []zipFileEntry
}

func newHashingZipWriter(w io.Writer) *hashingZipWriter {
	return &hashingZipWriter{
		zw: zip.NewWriter(w),
	}
}

// prepareHeader sets fields required by CreateRaw that Go's archive/zip does
// not populate automatically (unlike CreateHeader). This includes the reader
// version and MS-DOS modified date/time.
func prepareHeader(h *zip.FileHeader) {
	// ReaderVersion: 20 (2.0) is the minimum for DEFLATE.
	// Go's CreateRaw does not set this.
	h.ReaderVersion = 0x14 // 2.0
	// Use a fixed date/time for deterministic output.
	// 2020-01-01 00:00:00 in MS-DOS format.
	// Date: (40 << 9) | (1 << 5) | 1 = 0x5021
	// Time: 0x0000
	h.ModifiedDate = 0x5021
	h.ModifiedTime = 0x0000
}

// writeFile writes data to the ZIP as independently compressed 64KB blocks.
// It returns the zipFileEntry with block hashes and LfhSize.
// Empty files are stored uncompressed.
func (h *hashingZipWriter) writeFile(name string, data []byte) (zipFileEntry, error) {
	// Empty files use STORE to avoid issues with empty DEFLATE streams.
	if len(data) == 0 {
		return h.writeFileStore(name, data)
	}

	blocks, compressedData, err := compressBlocks(data)
	if err != nil {
		return zipFileEntry{}, err
	}

	crc := crc32.ChecksumIEEE(data)

	header := &zip.FileHeader{
		Name:               name,
		Method:             zip.Deflate,
		CRC32:              crc,
		CompressedSize64:   uint64(len(compressedData)),
		UncompressedSize64: uint64(len(data)),
	}
	// Ensure we use ZIP64 extensions if needed, but also set 32-bit fields.
	if len(compressedData) < 0xFFFFFFFF {
		header.CompressedSize = uint32(len(compressedData))
	}
	if len(data) < 0xFFFFFFFF {
		header.UncompressedSize = uint32(len(data))
	}
	prepareHeader(header)

	w, err := h.zw.CreateRaw(header)
	if err != nil {
		return zipFileEntry{}, err
	}

	if _, err := w.Write(compressedData); err != nil {
		return zipFileEntry{}, err
	}

	lfhSize := computeLfhSize(name)

	entry := zipFileEntry{
		Name:    name,
		Size:    uint64(len(data)),
		LfhSize: lfhSize,
		Blocks:  blocks,
	}
	h.entries = append(h.entries, entry)
	return entry, nil
}

// writeFileStore writes data to the ZIP without compression (STORE method).
func (h *hashingZipWriter) writeFileStore(name string, data []byte) (zipFileEntry, error) {
	blocks := computeBlockHashes(data)

	crc := crc32.ChecksumIEEE(data)

	header := &zip.FileHeader{
		Name:               name,
		Method:             zip.Store,
		CRC32:              crc,
		CompressedSize64:   uint64(len(data)),
		UncompressedSize64: uint64(len(data)),
	}
	if len(data) < 0xFFFFFFFF {
		header.CompressedSize = uint32(len(data))
		header.UncompressedSize = uint32(len(data))
	}
	prepareHeader(header)

	w, err := h.zw.CreateRaw(header)
	if err != nil {
		return zipFileEntry{}, err
	}

	if _, err := w.Write(data); err != nil {
		return zipFileEntry{}, err
	}

	lfhSize := computeLfhSize(name)

	entry := zipFileEntry{
		Name:    name,
		Size:    uint64(len(data)),
		LfhSize: lfhSize,
		Blocks:  blocks,
	}
	h.entries = append(h.entries, entry)
	return entry, nil
}

// close closes the underlying zip.Writer.
func (h *hashingZipWriter) close() error {
	return h.zw.Close()
}

// compressBlocks splits data into 64KB blocks, hashes each uncompressed block,
// and independently DEFLATE-compresses each block. Returns block entries and
// the concatenated compressed data.
//
// Each block is compressed with a fresh DEFLATE compressor for independent
// decompression. Intermediate blocks use Flush() (sync marker, no FINAL bit)
// and only the last block uses Close() (FINAL bit set). This produces a single
// valid DEFLATE stream that standard ZIP readers can decompress, while still
// allowing per-block random access as required by the MSIX block map.
func compressBlocks(data []byte) ([]blockEntry, []byte, error) {
	if len(data) == 0 {
		// Empty file: one block with hash of empty data.
		hash := sha256.Sum256(nil)
		return []blockEntry{{Hash: hash, CompressedSize: 0}}, nil, nil
	}

	var blocks []blockEntry
	var compressed bytes.Buffer

	numBlocks := (len(data) + blockSize - 1) / blockSize

	for i := 0; i < numBlocks; i++ {
		offset := i * blockSize
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		block := data[offset:end]

		hash := sha256.Sum256(block)

		startLen := compressed.Len()
		fw, err := flate.NewWriter(&compressed, flate.DefaultCompression)
		if err != nil {
			return nil, nil, err
		}
		if _, err := fw.Write(block); err != nil {
			fw.Close()
			return nil, nil, err
		}

		if i == numBlocks-1 {
			// Last block: Close() writes the FINAL bit to terminate the DEFLATE stream.
			if err := fw.Close(); err != nil {
				return nil, nil, err
			}
		} else {
			// Intermediate block: Flush() writes a sync marker (no FINAL bit),
			// keeping the stream valid for concatenation.
			if err := fw.Flush(); err != nil {
				fw.Close()
				return nil, nil, err
			}
		}

		blocks = append(blocks, blockEntry{
			Hash:           hash,
			CompressedSize: uint64(compressed.Len() - startLen),
		})
	}

	return blocks, compressed.Bytes(), nil
}

// computeBlockHashes computes SHA256 hashes for 64KB blocks without compression.
// Used for STORE'd files where CompressedSize is not tracked.
func computeBlockHashes(data []byte) []blockEntry {
	if len(data) == 0 {
		hash := sha256.Sum256(nil)
		return []blockEntry{{Hash: hash}}
	}

	var blocks []blockEntry
	for offset := 0; offset < len(data); offset += blockSize {
		end := offset + blockSize
		if end > len(data) {
			end = len(data)
		}
		hash := sha256.Sum256(data[offset:end])
		blocks = append(blocks, blockEntry{Hash: hash})
	}
	return blocks
}

// computeLfhSize returns the size of the local file header for the given file name.
// Local file header: 30 bytes fixed + filename length + extra field length.
// archive/zip typically uses a 20-byte extra field for ZIP64.
func computeLfhSize(name string) uint64 {
	// The local file header signature + fixed fields = 30 bytes.
	// archive/zip adds extended timestamp or ZIP64 extra fields.
	// We compute this as: signature(4) + version(2) + flags(2) + method(2) +
	// modtime(2) + moddate(2) + crc32(4) + compressedSize(4) + uncompressedSize(4) +
	// filenameLen(2) + extraLen(2) = 30 bytes + filename + extra.
	// archive/zip uses a data descriptor so sizes may be zero in the header,
	// but with CreateRaw, it writes them in the header.
	// The extra field is typically empty or minimal with CreateRaw.
	return uint64(30 + len(name))
}

// zipEndLocatorSize is the minimum size of the end of central directory record.
const zipEndLocatorSize = 22

// findCentralDirectoryOffset finds the offset and size of the central directory
// in a ZIP file stored in the given byte slice.
func findCentralDirectoryOffset(data []byte) (offset uint64, size uint64, err error) {
	// Search for End of Central Directory record from the end.
	// Signature: 0x06054b50
	minPos := len(data) - 65557 // max comment size is 65535
	if minPos < 0 {
		minPos = 0
	}

	eocdPos := -1
	for i := len(data) - zipEndLocatorSize; i >= minPos; i-- {
		if data[i] == 0x50 && data[i+1] == 0x4b && data[i+2] == 0x05 && data[i+3] == 0x06 {
			eocdPos = i
			break
		}
	}

	if eocdPos == -1 {
		return 0, 0, io.ErrUnexpectedEOF
	}

	// Check for ZIP64 end of central directory locator (just before EOCD).
	// Signature: 0x07064b50
	if eocdPos >= 20 {
		zip64LocPos := eocdPos - 20
		if data[zip64LocPos] == 0x50 && data[zip64LocPos+1] == 0x4b && data[zip64LocPos+2] == 0x06 && data[zip64LocPos+3] == 0x07 {
			// Read ZIP64 end of central directory offset.
			zip64EocdOffset := binary.LittleEndian.Uint64(data[zip64LocPos+8 : zip64LocPos+16])
			if int(zip64EocdOffset)+56 <= len(data) {
				// ZIP64 end of central directory record.
				// Signature: 0x06064b50
				z64 := data[zip64EocdOffset:]
				if z64[0] == 0x50 && z64[1] == 0x4b && z64[2] == 0x06 && z64[3] == 0x06 {
					cdSize := binary.LittleEndian.Uint64(z64[40:48])
					cdOffset := binary.LittleEndian.Uint64(z64[48:56])
					return cdOffset, cdSize, nil
				}
			}
		}
	}

	// Standard EOCD.
	cdSize32 := binary.LittleEndian.Uint32(data[eocdPos+12 : eocdPos+16])
	cdOffset32 := binary.LittleEndian.Uint32(data[eocdPos+16 : eocdPos+20])

	return uint64(cdOffset32), uint64(cdSize32), nil
}
