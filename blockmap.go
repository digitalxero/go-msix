package msix

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
)

const blockMapNamespace = "http://schemas.microsoft.com/appx/2010/blockmap"

// blockMapXML is the root element of AppxBlockMap.xml.
type blockMapXML struct {
	XMLName xml.Name       `xml:"BlockMap"`
	NS      string         `xml:"xmlns,attr"`
	HashMethod string      `xml:"HashMethod,attr"`
	Files   []blockMapFile `xml:"File"`
}

// blockMapFile represents a file entry in the block map.
type blockMapFile struct {
	Name   string          `xml:"Name,attr"`
	Size   uint64          `xml:"Size,attr"`
	LfhSize uint64         `xml:"LfhSize,attr"`
	Blocks []blockMapBlock `xml:"Block"`
}

// blockMapBlock represents a block within a file in the block map.
type blockMapBlock struct {
	Hash string `xml:"Hash,attr"`
	Size uint64 `xml:"Size,attr,omitempty"` // Omitted for STORE'd files (uncompressed).
}

// marshalBlockMap generates the AppxBlockMap.xml content from file entries.
func marshalBlockMap(entries []zipFileEntry) ([]byte, error) {
	bm := blockMapXML{
		NS:         blockMapNamespace,
		HashMethod: "http://www.w3.org/2001/04/xmlenc#sha256",
	}

	for _, entry := range entries {
		f := blockMapFile{
			// Block map uses backslash path separators per Microsoft's MSIX specification.
			Name:    strings.ReplaceAll(entry.Name, "/", "\\"),
			Size:    entry.Size,
			LfhSize: entry.LfhSize,
		}

		for _, b := range entry.Blocks {
			block := blockMapBlock{
				Hash: base64.StdEncoding.EncodeToString(b.Hash[:]),
				Size: b.CompressedSize,
			}
			f.Blocks = append(f.Blocks, block)
		}

		bm.Files = append(bm.Files, f)
	}

	output, err := xml.MarshalIndent(bm, "", "  ")
	if err != nil {
		return nil, err
	}

	return append([]byte(xml.Header), output...), nil
}
