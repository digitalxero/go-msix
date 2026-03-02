package msix

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"
)

func TestMarshalBlockMap_SingleFile(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	entries := []zipFileEntry{
		{
			Name:    "test.txt",
			Size:    4,
			LfhSize: 43,
			Blocks: []blockEntry{
				{Hash: hash, CompressedSize: 12},
			},
		},
	}

	data, err := marshalBlockMap(entries)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)

	// Check XML header.
	if !strings.HasPrefix(s, "<?xml") {
		t.Fatal("missing XML header")
	}

	// Check namespace.
	if !strings.Contains(s, blockMapNamespace) {
		t.Fatal("missing block map namespace")
	}

	// Check file entry.
	if !strings.Contains(s, `Name="test.txt"`) {
		t.Fatal("missing file name")
	}
	if !strings.Contains(s, `Size="4"`) {
		t.Fatal("missing file size")
	}
	if !strings.Contains(s, `LfhSize="43"`) {
		t.Fatal("missing LfhSize")
	}

	// Check block hash.
	expectedHash := base64.StdEncoding.EncodeToString(hash[:])
	if !strings.Contains(s, expectedHash) {
		t.Fatal("missing block hash")
	}
}

func TestMarshalBlockMap_MultipleFiles(t *testing.T) {
	hash1 := sha256.Sum256([]byte("file1"))
	hash2 := sha256.Sum256([]byte("file2"))

	entries := []zipFileEntry{
		{
			Name: "a.txt", Size: 5, LfhSize: 35,
			Blocks: []blockEntry{{Hash: hash1, CompressedSize: 10}},
		},
		{
			Name: "b.exe", Size: 100, LfhSize: 35,
			Blocks: []blockEntry{{Hash: hash2, CompressedSize: 80}},
		},
	}

	data, err := marshalBlockMap(entries)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	if !strings.Contains(s, `Name="a.txt"`) || !strings.Contains(s, `Name="b.exe"`) {
		t.Fatal("missing file entries")
	}
}

func TestMarshalBlockMap_ValidXML(t *testing.T) {
	hash := sha256.Sum256([]byte("data"))
	entries := []zipFileEntry{
		{
			Name: "file.txt", Size: 4, LfhSize: 38,
			Blocks: []blockEntry{{Hash: hash, CompressedSize: 10}},
		},
	}

	data, err := marshalBlockMap(entries)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid XML.
	var parsed blockMapXML
	if err := xml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	if len(parsed.Files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(parsed.Files))
	}
	if parsed.Files[0].Name != "file.txt" {
		t.Fatalf("expected file.txt, got %s", parsed.Files[0].Name)
	}
}

func TestMarshalBlockMap_StoreFile_NoBlockSize(t *testing.T) {
	hash := sha256.Sum256([]byte("stored"))
	entries := []zipFileEntry{
		{
			Name: "stored.txt", Size: 6, LfhSize: 40,
			Blocks: []blockEntry{{Hash: hash, CompressedSize: 0}}, // STORE'd: no compressed size
		},
	}

	data, err := marshalBlockMap(entries)
	if err != nil {
		t.Fatal(err)
	}

	s := string(data)
	// Size attr with value 0 should be omitted (omitempty).
	if strings.Contains(s, `Size="0"`) {
		t.Fatal("Size=0 should be omitted for STORE'd files")
	}
}
