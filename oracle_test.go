package msix

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
)

// compressBlocks is the original in-memory block compressor, retained only as a
// test oracle. The streaming compressor (compressSourceToSpill) must produce
// byte-identical output to this; TestCompressSourceToSpill_OracleParity enforces it.
//
// It splits data into 64KB blocks, hashes each uncompressed block, and independently
// DEFLATE-compresses each block. Intermediate blocks use Flush() (sync marker, no
// FINAL bit) and only the last block uses Close() (FINAL bit set).
func compressBlocks(data []byte) ([]blockEntry, []byte, error) {
	if len(data) == 0 {
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
			if err := fw.Close(); err != nil {
				return nil, nil, err
			}
		} else {
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
