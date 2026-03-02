package msix

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestCompressBlocks_Empty(t *testing.T) {
	blocks, data, err := compressBlocks(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	if len(data) != 0 {
		t.Fatalf("expected no compressed data, got %d bytes", len(data))
	}
	// Hash of empty data.
	expected := sha256.Sum256(nil)
	if blocks[0].Hash != expected {
		t.Fatal("hash mismatch for empty block")
	}
}

func TestCompressBlocks_SmallData(t *testing.T) {
	input := []byte("hello world")
	blocks, data, err := compressBlocks(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	if len(data) == 0 {
		t.Fatal("expected compressed data")
	}
	expected := sha256.Sum256(input)
	if blocks[0].Hash != expected {
		t.Fatal("hash mismatch")
	}
	if blocks[0].CompressedSize != uint64(len(data)) {
		t.Fatalf("compressed size mismatch: got %d, expected %d", blocks[0].CompressedSize, len(data))
	}
}

func TestCompressBlocks_Exactly64KB(t *testing.T) {
	input := make([]byte, blockSize)
	for i := range input {
		input[i] = byte(i % 256)
	}
	blocks, _, err := compressBlocks(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	expected := sha256.Sum256(input)
	if blocks[0].Hash != expected {
		t.Fatal("hash mismatch")
	}
}

func TestCompressBlocks_MultiBlock(t *testing.T) {
	input := make([]byte, blockSize*2+100)
	for i := range input {
		input[i] = byte(i % 256)
	}
	blocks, _, err := compressBlocks(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks, got %d", len(blocks))
	}

	// Verify each block hash.
	h1 := sha256.Sum256(input[0:blockSize])
	h2 := sha256.Sum256(input[blockSize : blockSize*2])
	h3 := sha256.Sum256(input[blockSize*2:])

	if blocks[0].Hash != h1 {
		t.Fatal("block 0 hash mismatch")
	}
	if blocks[1].Hash != h2 {
		t.Fatal("block 1 hash mismatch")
	}
	if blocks[2].Hash != h3 {
		t.Fatal("block 2 hash mismatch")
	}
}

func TestComputeLfhSize(t *testing.T) {
	// LFH = 30 bytes fixed + filename length.
	name := "test/file.txt"
	size := computeLfhSize(name)
	expected := uint64(30 + len(name))
	if size != expected {
		t.Fatalf("expected LFH size %d, got %d", expected, size)
	}
}

func TestHashingZipWriter_WriteAndRead(t *testing.T) {
	var buf bytes.Buffer
	hw := newHashingZipWriter(&buf)

	testData := []byte("test file content")
	_, err := hw.writeFile("test.txt", testData)
	if err != nil {
		t.Fatal(err)
	}

	if err := hw.close(); err != nil {
		t.Fatal(err)
	}

	// Read back.
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if len(reader.File) != 1 {
		t.Fatalf("expected 1 file, got %d", len(reader.File))
	}
	if reader.File[0].Name != "test.txt" {
		t.Fatalf("expected test.txt, got %s", reader.File[0].Name)
	}

	rc, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	var content bytes.Buffer
	if _, err := content.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content.Bytes(), testData) {
		t.Fatalf("content mismatch: got %q, expected %q", content.Bytes(), testData)
	}
}

func TestHashingZipWriter_StoreFile(t *testing.T) {
	var buf bytes.Buffer
	hw := newHashingZipWriter(&buf)

	testData := []byte("stored content")
	_, err := hw.writeFileStore("stored.txt", testData)
	if err != nil {
		t.Fatal(err)
	}

	if err := hw.close(); err != nil {
		t.Fatal(err)
	}

	// Read back.
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if reader.File[0].Method != zip.Store {
		t.Fatal("expected STORE method")
	}
}

func TestFindCentralDirectoryOffset(t *testing.T) {
	var buf bytes.Buffer
	hw := newHashingZipWriter(&buf)

	_, err := hw.writeFile("a.txt", []byte("aaa"))
	if err != nil {
		t.Fatal(err)
	}
	if err := hw.close(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	offset, size, err := findCentralDirectoryOffset(data)
	if err != nil {
		t.Fatal(err)
	}

	if offset == 0 && size == 0 {
		t.Fatal("central directory not found")
	}
	if offset >= uint64(len(data)) {
		t.Fatal("offset out of range")
	}
	if offset+size > uint64(len(data)) {
		t.Fatal("central directory extends beyond file")
	}
}

func TestComputeBlockHashes(t *testing.T) {
	data := []byte("test data for hashing")
	blocks := computeBlockHashes(data)
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block, got %d", len(blocks))
	}
	expected := sha256.Sum256(data)
	if blocks[0].Hash != expected {
		t.Fatal("hash mismatch")
	}
	// STORE'd blocks should not have CompressedSize set.
	if blocks[0].CompressedSize != 0 {
		t.Fatal("expected zero CompressedSize for STORE block")
	}
}
