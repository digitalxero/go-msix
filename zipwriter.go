package msix

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/binary"
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

// prepareHeader sets fields required by CreateRaw that Go's archive/zip does
// not populate automatically (unlike CreateHeader). This includes the reader
// version and MS-DOS modified date/time, and keeps output deterministic.
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

// computeLfhSize returns the size of the local file header for the given file name.
// With CreateRaw and no extra field, archive/zip writes a 30-byte fixed header plus
// the file name, with the sizes stored inline (no data descriptor). This must match
// the actual on-disk header so the block map's LfhSize is correct.
func computeLfhSize(name string) uint64 {
	// signature(4) + version(2) + flags(2) + method(2) + modtime(2) + moddate(2) +
	// crc32(4) + compressedSize(4) + uncompressedSize(4) + filenameLen(2) +
	// extraLen(2) = 30 bytes + filename (+ extra, which is 0 with CreateRaw).
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
