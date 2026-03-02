package msix

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// SignOptions configures code signing for the MSIX package.
type SignOptions struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertChain   []*x509.Certificate
}

// fileEntry represents a file to be added to the package.
type fileEntry struct {
	packagePath string
	data        []byte
}

// Builder constructs an MSIX package.
type Builder struct {
	Manifest    Manifest
	SignOptions *SignOptions
	files       []fileEntry
}

// NewBuilder creates a new MSIX package builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// AddFile adds a file from disk to the package.
func (b *Builder) AddFile(packagePath, diskPath string) error {
	data, err := os.ReadFile(diskPath)
	if err != nil {
		return fmt.Errorf("msix: reading %s: %w", diskPath, err)
	}
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		data:        data,
	})
	return nil
}

// AddFileFromBytes adds a file from a byte slice to the package.
func (b *Builder) AddFileFromBytes(packagePath string, data []byte) {
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		data:        append([]byte(nil), data...),
	})
}

// AddFileFromReader adds a file from a reader to the package.
func (b *Builder) AddFileFromReader(packagePath string, r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("msix: reading data for %s: %w", packagePath, err)
	}
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		data:        data,
	})
	return nil
}

// Build writes the MSIX package to the given writer.
func (b *Builder) Build(w io.Writer) error {
	// Step 1: Render manifest.
	manifestData, err := renderManifest(&b.Manifest)
	if err != nil {
		return fmt.Errorf("msix: rendering manifest: %w", err)
	}

	if b.SignOptions != nil {
		return b.buildSigned(w, manifestData)
	}
	return b.buildUnsigned(w, manifestData)
}

func (b *Builder) buildUnsigned(w io.Writer, manifestData []byte) error {
	hw := newHashingZipWriter(w)

	// Step 2: Write payload files and collect block entries.
	var blockMapEntries []zipFileEntry
	allFiles := []string{}

	// Sort files for deterministic output.
	sorted := make([]fileEntry, len(b.files))
	copy(sorted, b.files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].packagePath < sorted[j].packagePath
	})

	for _, f := range sorted {
		entry, err := hw.writeFile(f.packagePath, f.data)
		if err != nil {
			return fmt.Errorf("msix: writing %s: %w", f.packagePath, err)
		}
		blockMapEntries = append(blockMapEntries, entry)
		allFiles = append(allFiles, f.packagePath)
	}

	// Step 3: Compute block entries for AppxManifest.xml.
	manifestBlocks, _, err := compressBlocks(manifestData)
	if err != nil {
		return fmt.Errorf("msix: computing manifest blocks: %w", err)
	}

	// Write AppxManifest.xml.
	manifestEntry, err := hw.writeFile("AppxManifest.xml", manifestData)
	if err != nil {
		return fmt.Errorf("msix: writing manifest: %w", err)
	}
	_ = manifestBlocks
	blockMapEntries = append(blockMapEntries, manifestEntry)
	allFiles = append(allFiles, "AppxManifest.xml")

	// Step 4: Generate AppxBlockMap.xml.
	blockMapData, err := marshalBlockMap(blockMapEntries)
	if err != nil {
		return fmt.Errorf("msix: generating block map: %w", err)
	}

	// Step 5: Write AppxBlockMap.xml to ZIP.
	if _, err := hw.writeFile("AppxBlockMap.xml", blockMapData); err != nil {
		return fmt.Errorf("msix: writing block map: %w", err)
	}
	allFiles = append(allFiles, "AppxBlockMap.xml")

	// Step 6: Generate and write [Content_Types].xml.
	contentTypesData, err := marshalContentTypes(allFiles)
	if err != nil {
		return fmt.Errorf("msix: generating content types: %w", err)
	}
	if _, err := hw.writeFileStore("[Content_Types].xml", contentTypesData); err != nil {
		return fmt.Errorf("msix: writing content types: %w", err)
	}

	// Step 7: Close ZIP.
	return hw.close()
}

func (b *Builder) buildSigned(w io.Writer, manifestData []byte) error {
	// Two-pass approach: build unsigned to buffer, then compute digests and rebuild with signature.

	// Pass 1: Build unsigned package to buffer.
	var buf bytes.Buffer
	if err := b.buildUnsigned(&buf, manifestData); err != nil {
		return fmt.Errorf("msix: building unsigned package for signing: %w", err)
	}

	unsignedBytes := buf.Bytes()

	// Find central directory offset.
	cdOffset, cdSize, err := findCentralDirectoryOffset(unsignedBytes)
	if err != nil {
		return fmt.Errorf("msix: finding central directory: %w", err)
	}

	// Compute AXPC: hash of everything before central directory.
	axpc := hashBytes(unsignedBytes[:cdOffset])

	// Compute AXCD: hash of central directory.
	axcd := hashBytes(unsignedBytes[cdOffset : cdOffset+cdSize])

	// Compute AXBM: hash of uncompressed AppxBlockMap.xml.
	// We need to regenerate block map data.
	blockMapData, err := b.generateBlockMapData(manifestData)
	if err != nil {
		return fmt.Errorf("msix: regenerating block map for signing: %w", err)
	}
	axbm := hashBytes(blockMapData)

	// Compute AXCT: hash of uncompressed [Content_Types].xml.
	contentTypesData, err := b.generateContentTypesData(manifestData)
	if err != nil {
		return fmt.Errorf("msix: regenerating content types for signing: %w", err)
	}
	axct := hashBytes(contentTypesData)

	// AXCI: hash of CodeIntegrity.cat (zeros if absent).
	var axci [32]byte

	// Build the signature.
	sig, err := createSignature(axpc, axcd, axct, axbm, axci, b.SignOptions)
	if err != nil {
		return fmt.Errorf("msix: creating signature: %w", err)
	}

	// Pass 2: Rebuild package with signature.
	hw := newHashingZipWriter(w)

	var blockMapEntries []zipFileEntry
	allFiles := []string{}

	sorted := make([]fileEntry, len(b.files))
	copy(sorted, b.files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].packagePath < sorted[j].packagePath
	})

	for _, f := range sorted {
		entry, err := hw.writeFile(f.packagePath, f.data)
		if err != nil {
			return fmt.Errorf("msix: writing %s: %w", f.packagePath, err)
		}
		blockMapEntries = append(blockMapEntries, entry)
		allFiles = append(allFiles, f.packagePath)
	}

	manifestEntry, err := hw.writeFile("AppxManifest.xml", manifestData)
	if err != nil {
		return fmt.Errorf("msix: writing manifest: %w", err)
	}
	blockMapEntries = append(blockMapEntries, manifestEntry)
	allFiles = append(allFiles, "AppxManifest.xml")

	finalBlockMapData, err := marshalBlockMap(blockMapEntries)
	if err != nil {
		return fmt.Errorf("msix: generating block map: %w", err)
	}
	if _, err := hw.writeFile("AppxBlockMap.xml", finalBlockMapData); err != nil {
		return fmt.Errorf("msix: writing block map: %w", err)
	}
	allFiles = append(allFiles, "AppxBlockMap.xml")

	// Write signature.
	if _, err := hw.writeFileStore("AppxSignature.p7x", sig); err != nil {
		return fmt.Errorf("msix: writing signature: %w", err)
	}
	allFiles = append(allFiles, "AppxSignature.p7x")

	finalContentTypes, err := marshalContentTypes(allFiles)
	if err != nil {
		return fmt.Errorf("msix: generating content types: %w", err)
	}
	if _, err := hw.writeFileStore("[Content_Types].xml", finalContentTypes); err != nil {
		return fmt.Errorf("msix: writing content types: %w", err)
	}

	return hw.close()
}

// generateBlockMapData regenerates block map XML bytes for digest computation.
func (b *Builder) generateBlockMapData(manifestData []byte) ([]byte, error) {
	var entries []zipFileEntry

	sorted := make([]fileEntry, len(b.files))
	copy(sorted, b.files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].packagePath < sorted[j].packagePath
	})

	for _, f := range sorted {
		blocks, _, err := compressBlocks(f.data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, zipFileEntry{
			Name:    f.packagePath,
			Size:    uint64(len(f.data)),
			LfhSize: computeLfhSize(f.packagePath),
			Blocks:  blocks,
		})
	}

	manifestBlocks, _, err := compressBlocks(manifestData)
	if err != nil {
		return nil, err
	}
	entries = append(entries, zipFileEntry{
		Name:    "AppxManifest.xml",
		Size:    uint64(len(manifestData)),
		LfhSize: computeLfhSize("AppxManifest.xml"),
		Blocks:  manifestBlocks,
	})

	return marshalBlockMap(entries)
}

// generateContentTypesData regenerates content types XML bytes for digest computation.
func (b *Builder) generateContentTypesData(manifestData []byte) ([]byte, error) {
	allFiles := []string{}

	sorted := make([]fileEntry, len(b.files))
	copy(sorted, b.files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].packagePath < sorted[j].packagePath
	})

	for _, f := range sorted {
		allFiles = append(allFiles, f.packagePath)
	}
	allFiles = append(allFiles, "AppxManifest.xml", "AppxBlockMap.xml")

	return marshalContentTypes(allFiles)
}

func normalizePackagePath(p string) string {
	// Use forward slashes and clean the path.
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	return p
}
