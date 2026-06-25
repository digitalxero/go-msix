package msix

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressBlocks_Empty(t *testing.T) {
	blocks, data, err := compressBlocks(nil)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Empty(t, data)
	assert.Equal(t, sha256.Sum256(nil), blocks[0].Hash)
}

func TestCompressBlocks_SmallData(t *testing.T) {
	input := []byte("hello world")
	blocks, data, err := compressBlocks(input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.NotEmpty(t, data)
	assert.Equal(t, sha256.Sum256(input), blocks[0].Hash)
	assert.Equal(t, uint64(len(data)), blocks[0].CompressedSize)
}

func TestCompressBlocks_Exactly64KB(t *testing.T) {
	input := make([]byte, blockSize)
	for i := range input {
		input[i] = byte(i % 256)
	}
	blocks, _, err := compressBlocks(input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, sha256.Sum256(input), blocks[0].Hash)
}

func TestCompressBlocks_MultiBlock(t *testing.T) {
	input := make([]byte, blockSize*2+100)
	for i := range input {
		input[i] = byte(i % 256)
	}
	blocks, _, err := compressBlocks(input)
	require.NoError(t, err)
	require.Len(t, blocks, 3)
	assert.Equal(t, sha256.Sum256(input[0:blockSize]), blocks[0].Hash)
	assert.Equal(t, sha256.Sum256(input[blockSize:blockSize*2]), blocks[1].Hash)
	assert.Equal(t, sha256.Sum256(input[blockSize*2:]), blocks[2].Hash)
}

func TestComputeLfhSize(t *testing.T) {
	name := "test/file.txt"
	assert.Equal(t, uint64(30+len(name)), computeLfhSize(name))
}

func TestFindCentralDirectoryOffset(t *testing.T) {
	var buf bytes.Buffer
	err := goldenBaseBuilder().
		AddFileFromBytes("a.txt", []byte("aaa")).
		Build(context.Background(), &buf)
	require.NoError(t, err)

	data := buf.Bytes()
	offset, size, err := findCentralDirectoryOffset(data)
	require.NoError(t, err)
	assert.False(t, offset == 0 && size == 0, "central directory not found")
	assert.Less(t, offset, uint64(len(data)), "offset out of range")
	assert.LessOrEqual(t, offset+size, uint64(len(data)), "central directory extends beyond file")
}
