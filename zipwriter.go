package msix

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
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

// Fixed MS-DOS date/time for deterministic output: 2020-01-01 00:00:00.
// Date: (40 << 9) | (1 << 5) | 1 = 0x5021, Time: 0x0000.
const (
	zipModDate = 0x5021
	zipModTime = 0x0000

	// zipVersionNeeded is 2.0, the minimum for DEFLATE, matching what
	// signtool emits in both local and central headers of small entries.
	zipVersionNeeded = 0x14
	// zipVersionZip64 marks structures that require ZIP64 (4.5).
	zipVersionZip64 = 0x2D
)

// computeLfhSize returns the size of the local file header for the given file name:
// a 30-byte fixed header plus the file name, sizes stored inline, no extra field and
// no data descriptor. This must match the actual on-disk header so the block map's
// LfhSize is correct (signtool preserves these local records verbatim when
// re-signing, confirming the layout).
func computeLfhSize(name string) uint64 {
	// signature(4) + version(2) + flags(2) + method(2) + modtime(2) + moddate(2) +
	// crc32(4) + compressedSize(4) + uncompressedSize(4) + filenameLen(2) +
	// extraLen(2) = 30 bytes + filename.
	return uint64(30 + len(name))
}

// writeCanonicalZip serializes the entries in the canonical MSIX container form
// that Windows AppxSIP expects — the same shape makeappx/signtool produce:
//
//   - plain local records (30+name header, inline sizes, no data descriptors)
//   - central directory entries with "version made by" 4.5
//   - always-present ZIP64 EOCD record + ZIP64 locator, followed by a classic
//     EOCD stub whose counts/size/offset are 0xFFFF/0xFFFFFFFF sentinels
//
// AppxSIP reconstructs the "unsigned view" of a signed package in this form
// when it recomputes the AXPC/AXCD digests; a classic (non-ZIP64) container
// hashes differently under Windows even when every byte is self-consistent,
// which surfaced as Get-AuthenticodeSignature reporting HashMismatch.
func writeCanonicalZip(w io.Writer, entries []*compressedEntry) error {
	bw := bufio.NewWriterSize(w, 64*1024)

	var offset uint64
	offsets := make([]uint64, len(entries))
	for i, e := range entries {
		offsets[i] = offset
		if err := writeLocalRecord(bw, e); err != nil {
			return err
		}
		offset += e.lfhSize + e.compressedSize
	}

	cdOffset := offset
	var cdSize uint64
	for i, e := range entries {
		n, err := writeCentralDirectoryEntry(bw, e, offsets[i])
		if err != nil {
			return err
		}
		cdSize += n
	}

	if err := writeEndRecords(bw, uint64(len(entries)), cdSize, cdOffset); err != nil {
		return err
	}
	return bw.Flush()
}

// writeLocalRecord emits the local file header and the entry's bytes (compressed
// spill for Deflate, source bytes for Store).
func writeLocalRecord(w io.Writer, e *compressedEntry) error {
	if e.compressedSize >= 0xFFFFFFFF || e.uncompressedSize >= 0xFFFFFFFF {
		return fmt.Errorf("msix: entry %s is %d bytes; entries of 4 GiB or more are not supported", e.name, e.uncompressedSize)
	}
	var h [30]byte
	binary.LittleEndian.PutUint32(h[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(h[4:6], zipVersionNeeded)
	// flags(6:8) = 0, no data descriptor
	binary.LittleEndian.PutUint16(h[8:10], e.method)
	binary.LittleEndian.PutUint16(h[10:12], zipModTime)
	binary.LittleEndian.PutUint16(h[12:14], zipModDate)
	binary.LittleEndian.PutUint32(h[14:18], e.crc32)
	binary.LittleEndian.PutUint32(h[18:22], uint32(e.compressedSize))
	binary.LittleEndian.PutUint32(h[22:26], uint32(e.uncompressedSize))
	binary.LittleEndian.PutUint16(h[26:28], uint16(len(e.name)))
	// extraLen(28:30) = 0
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, e.name); err != nil {
		return err
	}

	var src io.ReadCloser
	var err error
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

// writeCentralDirectoryEntry emits one central directory header and returns its
// size. Offsets of 4 GiB or more get the 0xFFFFFFFF sentinel plus a ZIP64 extra
// field (entry sizes that large are rejected at the local record).
func writeCentralDirectoryEntry(w io.Writer, e *compressedEntry, offset uint64) (uint64, error) {
	zip64 := offset >= 0xFFFFFFFF
	var extra []byte
	offset32 := uint32(offset)
	version := uint16(zipVersionNeeded)
	if zip64 {
		offset32 = 0xFFFFFFFF
		version = zipVersionZip64
		extra = make([]byte, 12)
		binary.LittleEndian.PutUint16(extra[0:2], 0x0001) // ZIP64 extra field id
		binary.LittleEndian.PutUint16(extra[2:4], 8)
		binary.LittleEndian.PutUint64(extra[4:12], offset)
	}

	var h [46]byte
	binary.LittleEndian.PutUint32(h[0:4], 0x02014b50)
	binary.LittleEndian.PutUint16(h[4:6], zipVersionZip64) // version made by 4.5, MS-DOS host
	binary.LittleEndian.PutUint16(h[6:8], version)
	// flags(8:10) = 0
	binary.LittleEndian.PutUint16(h[10:12], e.method)
	binary.LittleEndian.PutUint16(h[12:14], zipModTime)
	binary.LittleEndian.PutUint16(h[14:16], zipModDate)
	binary.LittleEndian.PutUint32(h[16:20], e.crc32)
	binary.LittleEndian.PutUint32(h[20:24], uint32(e.compressedSize))
	binary.LittleEndian.PutUint32(h[24:28], uint32(e.uncompressedSize))
	binary.LittleEndian.PutUint16(h[28:30], uint16(len(e.name)))
	binary.LittleEndian.PutUint16(h[30:32], uint16(len(extra)))
	// commentLen(32:34), diskNo(34:36), internal attrs(36:38), external attrs(38:42) = 0
	binary.LittleEndian.PutUint32(h[42:46], offset32)
	if _, err := w.Write(h[:]); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(w, e.name); err != nil {
		return 0, err
	}
	if _, err := w.Write(extra); err != nil {
		return 0, err
	}
	return uint64(46 + len(e.name) + len(extra)), nil
}

// writeEndRecords emits the canonical trailer: ZIP64 EOCD record, ZIP64 locator,
// then a classic EOCD whose counts/size/offset are all sentinels — exactly the
// byte shape signtool/makeappx produce regardless of archive size.
func writeEndRecords(w io.Writer, entries, cdSize, cdOffset uint64) error {
	var z64 [56]byte
	binary.LittleEndian.PutUint32(z64[0:4], 0x06064b50)
	binary.LittleEndian.PutUint64(z64[4:12], 44) // record size excluding sig+size
	binary.LittleEndian.PutUint16(z64[12:14], zipVersionZip64)
	binary.LittleEndian.PutUint16(z64[14:16], zipVersionZip64)
	// diskNo(16:20), cdDisk(20:24) = 0
	binary.LittleEndian.PutUint64(z64[24:32], entries)
	binary.LittleEndian.PutUint64(z64[32:40], entries)
	binary.LittleEndian.PutUint64(z64[40:48], cdSize)
	binary.LittleEndian.PutUint64(z64[48:56], cdOffset)

	var loc [20]byte
	binary.LittleEndian.PutUint32(loc[0:4], 0x07064b50)
	// zip64 EOCD disk(4:8) = 0
	binary.LittleEndian.PutUint64(loc[8:16], cdOffset+cdSize)
	binary.LittleEndian.PutUint32(loc[16:20], 1) // total disks

	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)
	// diskNo(4:6), cdDisk(6:8) = 0
	binary.LittleEndian.PutUint16(eocd[8:10], 0xFFFF)
	binary.LittleEndian.PutUint16(eocd[10:12], 0xFFFF)
	binary.LittleEndian.PutUint32(eocd[12:16], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(eocd[16:20], 0xFFFFFFFF)
	// commentLen(20:22) = 0

	for _, b := range [][]byte{z64[:], loc[:], eocd[:]} {
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return nil
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
