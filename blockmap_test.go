package msix

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalBlockMap_SingleFile(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	entries := []zipFileEntry{
		{
			Name:    "test.txt",
			Size:    4,
			LfhSize: 43,
			Blocks:  []blockEntry{{Hash: hash, CompressedSize: 12}},
		},
	}

	data, err := marshalBlockMap(entries)
	require.NoError(t, err)
	s := string(data)

	assert.True(t, strings.HasPrefix(s, "<?xml"), "missing XML header")
	assert.Contains(t, s, blockMapNamespace, "missing block map namespace")
	assert.Contains(t, s, `Name="test.txt"`)
	assert.Contains(t, s, `Size="4"`)
	assert.Contains(t, s, `LfhSize="43"`)
	assert.Contains(t, s, base64.StdEncoding.EncodeToString(hash[:]), "missing block hash")
}

func TestMarshalBlockMap_MultipleFiles(t *testing.T) {
	hash1 := sha256.Sum256([]byte("file1"))
	hash2 := sha256.Sum256([]byte("file2"))

	entries := []zipFileEntry{
		{Name: "a.txt", Size: 5, LfhSize: 35, Blocks: []blockEntry{{Hash: hash1, CompressedSize: 10}}},
		{Name: "b.exe", Size: 100, LfhSize: 35, Blocks: []blockEntry{{Hash: hash2, CompressedSize: 80}}},
	}

	data, err := marshalBlockMap(entries)
	require.NoError(t, err)
	s := string(data)
	assert.Contains(t, s, `Name="a.txt"`)
	assert.Contains(t, s, `Name="b.exe"`)
}

func TestMarshalBlockMap_ValidXML(t *testing.T) {
	hash := sha256.Sum256([]byte("data"))
	entries := []zipFileEntry{
		{Name: "file.txt", Size: 4, LfhSize: 38, Blocks: []blockEntry{{Hash: hash, CompressedSize: 10}}},
	}

	data, err := marshalBlockMap(entries)
	require.NoError(t, err)

	var parsed blockMapXML
	require.NoError(t, xml.Unmarshal(data, &parsed))
	require.Len(t, parsed.Files, 1)
	assert.Equal(t, "file.txt", parsed.Files[0].Name)
}

func TestMarshalBlockMap_StoreFile_NoBlockSize(t *testing.T) {
	hash := sha256.Sum256([]byte("stored"))
	entries := []zipFileEntry{
		{Name: "stored.txt", Size: 6, LfhSize: 40, Blocks: []blockEntry{{Hash: hash, CompressedSize: 0}}},
	}

	data, err := marshalBlockMap(entries)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `Size="0"`, "Size=0 should be omitted for STORE'd files")
}
