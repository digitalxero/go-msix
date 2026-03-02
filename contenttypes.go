package msix

import (
	"encoding/xml"
	"path"
	"sort"
	"strings"
)

const contentTypesNamespace = "http://schemas.openxmlformats.org/package/2006/content-types"

// contentTypesXML is the root element of [Content_Types].xml.
type contentTypesXML struct {
	XMLName   xml.Name            `xml:"Types"`
	NS        string              `xml:"xmlns,attr"`
	Defaults  []contentDefault    `xml:"Default"`
	Overrides []contentOverride   `xml:"Override"`
}

type contentDefault struct {
	Extension   string `xml:"Extension,attr"`
	ContentType string `xml:"ContentType,attr"`
}

type contentOverride struct {
	PartName    string `xml:"PartName,attr"`
	ContentType string `xml:"ContentType,attr"`
}

// Known MIME types by extension.
var mimeTypes = map[string]string{
	".exe":  "application/x-msdownload",
	".dll":  "application/x-msdownload",
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
	".bmp":  "image/bmp",
	".json": "application/json",
	".xml":  "application/vnd.ms-appx.manifest+xml",
	".txt":  "text/plain",
	".html": "text/html",
	".htm":  "text/html",
	".css":  "text/css",
	".js":   "application/javascript",
	".wasm": "application/wasm",
	".pdf":  "application/pdf",
	".zip":  "application/zip",
	".wav":  "audio/wav",
	".mp3":  "audio/mpeg",
	".mp4":  "video/mp4",
	".ttf":  "application/x-font-ttf",
	".otf":  "font/otf",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".cfg":  "text/plain",
	".ini":  "text/plain",
	".yaml": "text/yaml",
	".yml":  "text/yaml",
	".toml": "text/plain",
	".dat":  "application/octet-stream",
	".bin":  "application/octet-stream",
	".cat":  "application/vnd.ms-pki.seccat",
	".p7x":  "application/octet-stream",
}

// marshalContentTypes generates the [Content_Types].xml content.
func marshalContentTypes(files []string) ([]byte, error) {
	// Collect unique extensions and map them.
	extMap := make(map[string]string)
	for _, f := range files {
		ext := strings.ToLower(path.Ext(f))
		if ext == "" {
			continue
		}
		if _, ok := extMap[ext]; !ok {
			mime := lookupMIME(ext)
			extMap[ext] = mime
		}
	}

	ct := contentTypesXML{
		NS: contentTypesNamespace,
	}

	// Add defaults for each extension (sorted for deterministic output).
	exts := make([]string, 0, len(extMap))
	for ext := range extMap {
		exts = append(exts, ext)
	}
	sort.Strings(exts)

	for _, ext := range exts {
		ct.Defaults = append(ct.Defaults, contentDefault{
			Extension:   strings.TrimPrefix(ext, "."),
			ContentType: extMap[ext],
		})
	}

	// Build a set of file names for conditional overrides.
	fileSet := make(map[string]bool, len(files))
	for _, f := range files {
		fileSet[f] = true
	}

	// Add overrides for MSIX metadata files.
	// The .xml extension default already covers AppxManifest.xml, so only
	// AppxBlockMap.xml needs an override to distinguish it from the manifest type.
	ct.Overrides = append(ct.Overrides, contentOverride{
		PartName:    "/AppxBlockMap.xml",
		ContentType: "application/vnd.ms-appx.blockmap+xml",
	})
	if fileSet["AppxSignature.p7x"] {
		ct.Overrides = append(ct.Overrides, contentOverride{
			PartName:    "/AppxSignature.p7x",
			ContentType: "application/vnd.ms-appx.signature",
		})
	}

	output, err := xml.MarshalIndent(ct, "", "  ")
	if err != nil {
		return nil, err
	}

	return append([]byte(xml.Header), output...), nil
}

func lookupMIME(ext string) string {
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}
