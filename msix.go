package msix

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Builder constructs an MSIX package. Configuration methods return the Builder for
// chaining; payload-source and configuration errors are deferred and surfaced from
// Build.
type Builder interface {
	WithIdentity(Identity) Builder
	WithProperties(Properties) Builder
	WithDependencies(Dependencies) Builder
	WithCapabilities(Capabilities) Builder
	AddResource(Resource) Builder
	AddApplication(Application) Builder
	AddPackageExtension(PackageExtension) Builder

	AddFile(packagePath, diskPath string) Builder
	AddFileFromBytes(packagePath string, data []byte) Builder
	AddFileFromReader(packagePath string, r io.Reader) Builder
	// AddFileSource adds a file from a re-openable source. open may be called more
	// than once during Build (e.g. once for digesting and once for output when
	// signing) and must return a fresh reader positioned at the start each time. The
	// contents are streamed and never fully loaded into memory.
	AddFileSource(packagePath string, open func() (io.ReadCloser, error)) Builder

	WithSigning(Signing) Builder

	// Build streams the MSIX package to w. The context is reserved for cancellation
	// of long-running builds.
	Build(ctx context.Context, w io.Writer) error
}

// NewBuilder creates a new MSIX package builder.
func NewBuilder() Builder {
	return &builder{}
}

// fileEntry represents a file to be added to the package. The bytes are never held
// in memory: source is a re-openable handle read lazily during Build.
type fileEntry struct {
	packagePath string
	source      fileSource
}

type builder struct {
	identity     Identity
	properties   Properties
	dependencies Dependencies
	capabilities Capabilities
	resources    []Resource
	applications []Application
	pkgExts      []PackageExtension

	files   []fileEntry
	signing Signing

	// tempDir is where compressed spills and reader spills are written. Empty means
	// the OS default temp dir.
	tempDir string
	// ownedTemps are temp files the builder created from one-shot readers; removed
	// when Build returns.
	ownedTemps []string

	// errs accumulates configuration errors deferred to Build.
	errs []error
}

func (b *builder) WithIdentity(i Identity) Builder         { b.identity = i; return b }
func (b *builder) WithProperties(p Properties) Builder     { b.properties = p; return b }
func (b *builder) WithDependencies(d Dependencies) Builder { b.dependencies = d; return b }
func (b *builder) WithCapabilities(c Capabilities) Builder { b.capabilities = c; return b }
func (b *builder) AddResource(r Resource) Builder          { b.resources = append(b.resources, r); return b }
func (b *builder) AddApplication(a Application) Builder {
	b.applications = append(b.applications, a)
	return b
}
func (b *builder) AddPackageExtension(e PackageExtension) Builder {
	b.pkgExts = append(b.pkgExts, e)
	return b
}
func (b *builder) WithSigning(s Signing) Builder { b.signing = s; return b }

// AddFile adds a file from disk. The file is opened lazily during Build and
// streamed; its contents are never fully loaded into memory.
func (b *builder) AddFile(packagePath, diskPath string) Builder {
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		source:      diskFileSource{path: diskPath},
	})
	return b
}

// AddFileFromBytes adds a file from a byte slice.
func (b *builder) AddFileFromBytes(packagePath string, data []byte) Builder {
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		source:      bytesFileSource{data: append([]byte(nil), data...)},
	})
	return b
}

// AddFileFromReader adds a file from a (possibly one-shot) reader. The reader is
// streamed to a temp file so the source becomes re-openable; the temp file is
// removed when Build returns. The reader is never fully buffered in memory.
func (b *builder) AddFileFromReader(packagePath string, r io.Reader) Builder {
	f, err := os.CreateTemp(b.tempDir, "msix-src-*")
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("msix: creating temp for %s: %w", packagePath, err))
		return b
	}
	tmp := f.Name()
	b.ownedTemps = append(b.ownedTemps, tmp)
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		b.errs = append(b.errs, fmt.Errorf("msix: reading data for %s: %w", packagePath, err))
		return b
	}
	if err := f.Close(); err != nil {
		b.errs = append(b.errs, fmt.Errorf("msix: writing temp for %s: %w", packagePath, err))
		return b
	}
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		source:      diskFileSource{path: tmp},
	})
	return b
}

// AddFileSource adds a file from a caller-supplied re-openable source.
func (b *builder) AddFileSource(packagePath string, open func() (io.ReadCloser, error)) Builder {
	b.files = append(b.files, fileEntry{
		packagePath: normalizePackagePath(packagePath),
		source:      funcFileSource{opener: open},
	})
	return b
}

// Build assembles and streams the MSIX package to w.
func (b *builder) Build(ctx context.Context, w io.Writer) error {
	_ = ctx
	defer b.cleanupOwnedTemps()

	if err := errors.Join(b.errs...); err != nil {
		return err
	}

	m := b.assembleManifest()
	if err := validateManifest(m); err != nil {
		return err
	}

	manifestData, err := renderManifest(m)
	if err != nil {
		return fmt.Errorf("msix: rendering manifest: %w", err)
	}

	if b.signing != nil {
		creds, err := b.signing.(*signing).resolve()
		if err != nil {
			return fmt.Errorf("msix: resolving signing credentials: %w", err)
		}
		return b.buildSigned(w, manifestData, creds)
	}
	return b.buildUnsigned(w, manifestData)
}

// assembleManifest translates the configured sub-builders into the internal
// template data structure.
func (b *builder) assembleManifest() *manifestData {
	m := &manifestData{}
	if b.identity != nil {
		m.Identity = b.identity.(*identity).data()
	}
	if b.properties != nil {
		m.Properties = b.properties.(*properties).data()
	}
	if b.dependencies != nil {
		m.Dependencies = b.dependencies.(*dependencies).data()
	}
	if b.capabilities != nil {
		m.Capabilities = b.capabilities.(*capabilities).data()
	}
	for _, r := range b.resources {
		m.Resources = append(m.Resources, r.(*resource).data())
	}
	for _, a := range b.applications {
		m.Applications = append(m.Applications, a.(*application).data())
	}
	for _, e := range b.pkgExts {
		m.Extensions = append(m.Extensions, e.toPkgExtData())
	}
	return m
}

// validateManifest checks required fields, aggregating all problems.
func validateManifest(m *manifestData) error {
	var errs []error
	if m.Identity.Name == "" {
		errs = append(errs, errors.New("msix: identity name is required"))
	}
	if m.Identity.Version == "" {
		errs = append(errs, errors.New("msix: identity version is required"))
	}
	if m.Identity.Publisher == "" {
		errs = append(errs, errors.New("msix: identity publisher is required"))
	}
	for i, a := range m.Applications {
		if a.ID == "" {
			errs = append(errs, fmt.Errorf("msix: application[%d] id is required", i))
		}
		ve := a.VisualElements
		if ve.DisplayName == "" {
			errs = append(errs, fmt.Errorf("msix: application[%d] visual elements display name is required", i))
		}
		if ve.BackgroundColor == "" {
			errs = append(errs, fmt.Errorf("msix: application[%d] visual elements background color is required", i))
		}
		if ve.Square150x150Logo == "" {
			errs = append(errs, fmt.Errorf("msix: application[%d] square 150x150 logo is required", i))
		}
		if ve.Square44x44Logo == "" {
			errs = append(errs, fmt.Errorf("msix: application[%d] square 44x44 logo is required", i))
		}
	}
	return errors.Join(errs...)
}

func (b *builder) cleanupOwnedTemps() {
	for _, p := range b.ownedTemps {
		os.Remove(p)
	}
}

// sortedFiles returns the payload files ordered by package path for deterministic output.
func (b *builder) sortedFiles() []fileEntry {
	s := make([]fileEntry, len(b.files))
	copy(s, b.files)
	sort.Slice(s, func(i, j int) bool {
		return s[i].packagePath < s[j].packagePath
	})
	return s
}

// buildCtx tracks the compressed spills created during a single build so they can all
// be cleaned up, even on error.
type buildCtx struct {
	b      *builder
	spills []string
}

func (c *buildCtx) compress(name string, src fileSource, forceStore bool) (*compressedEntry, error) {
	e, err := compressSourceToSpill(name, src, forceStore, c.b.tempDir)
	if err != nil {
		return nil, err
	}
	if e.spillPath != "" {
		c.spills = append(c.spills, e.spillPath)
	}
	return e, nil
}

func (c *buildCtx) cleanup() {
	for _, p := range c.spills {
		os.Remove(p)
	}
	c.spills = nil
}

// prepareCore compresses the payload files and the manifest to spills (collecting
// block-map metadata) and renders the block map. It returns the payload+manifest
// entries, the rendered block map bytes, and the ordered list of part names
// (payloads + AppxManifest.xml) used for content-types generation.
func (c *buildCtx) prepareCore(manifestData []byte) (core []*compressedEntry, blockMapBytes []byte, names []string, err error) {
	var bm []zipFileEntry
	for _, f := range c.b.sortedFiles() {
		e, err := c.compress(f.packagePath, f.source, false)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("msix: compressing %s: %w", f.packagePath, err)
		}
		core = append(core, e)
		bm = append(bm, e.zipFileEntry())
		names = append(names, f.packagePath)
	}

	manifestEntry, err := c.compress("AppxManifest.xml", bytesFileSource{data: manifestData}, false)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msix: compressing manifest: %w", err)
	}
	core = append(core, manifestEntry)
	bm = append(bm, manifestEntry.zipFileEntry())
	names = append(names, "AppxManifest.xml")

	blockMapBytes, err = marshalBlockMap(bm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msix: generating block map: %w", err)
	}
	return core, blockMapBytes, names, nil
}

func (b *builder) buildUnsigned(w io.Writer, manifestData []byte) error {
	c := &buildCtx{b: b}
	defer c.cleanup()

	core, blockMapBytes, names, err := c.prepareCore(manifestData)
	if err != nil {
		return err
	}

	blockMapEntry, err := c.compress("AppxBlockMap.xml", bytesFileSource{data: blockMapBytes}, false)
	if err != nil {
		return fmt.Errorf("msix: compressing block map: %w", err)
	}
	names = append(names, "AppxBlockMap.xml")

	contentTypes, err := marshalContentTypes(names)
	if err != nil {
		return fmt.Errorf("msix: generating content types: %w", err)
	}
	contentTypesEntry, err := c.compress("[Content_Types].xml", bytesFileSource{data: contentTypes}, false)
	if err != nil {
		return fmt.Errorf("msix: preparing content types: %w", err)
	}

	return writeZip(w, append(core, blockMapEntry, contentTypesEntry))
}

func (b *builder) buildSigned(w io.Writer, manifestData []byte, creds *signingCreds) error {
	c := &buildCtx{b: b}
	defer c.cleanup()

	core, blockMapBytes, names, err := c.prepareCore(manifestData)
	if err != nil {
		return err
	}

	blockMapEntry, err := c.compress("AppxBlockMap.xml", bytesFileSource{data: blockMapBytes}, false)
	if err != nil {
		return fmt.Errorf("msix: compressing block map: %w", err)
	}

	// Hash the final content types, including the signature declaration.
	// Only AppxSignature.p7x itself is excluded from the digest layout.
	names = append(names, "AppxBlockMap.xml", "AppxSignature.p7x")
	contentTypes, err := marshalContentTypes(names)
	if err != nil {
		return fmt.Errorf("msix: generating content types: %w", err)
	}
	contentTypesEntry, err := c.compress("[Content_Types].xml", bytesFileSource{data: contentTypes}, false)
	if err != nil {
		return fmt.Errorf("msix: preparing content types: %w", err)
	}

	axbm := hashBytes(blockMapBytes)
	axct := hashBytes(contentTypes)
	var axci *[32]byte
	for _, entry := range core {
		if entry.name != "AppxMetadata/CodeIntegrity.cat" {
			continue
		}
		r, err := entry.source.open()
		if err != nil {
			return fmt.Errorf("msix: opening code integrity catalog: %w", err)
		}
		h := sha256.New()
		_, readErr := io.Copy(h, r)
		if err := errors.Join(readErr, r.Close()); err != nil {
			return fmt.Errorf("msix: hashing code integrity catalog: %w", err)
		}
		digest := [32]byte(h.Sum(nil))
		axci = &digest
	}

	unsignedLayout := append(core, blockMapEntry, contentTypesEntry)
	axpc, axcd, err := computeDigests(unsignedLayout)
	if err != nil {
		return fmt.Errorf("msix: computing digests: %w", err)
	}

	sig, err := createSignature(axpc, axcd, axct, axbm, axci, creds)
	if err != nil {
		return fmt.Errorf("msix: creating signature: %w", err)
	}

	signatureEntry, err := c.compress("AppxSignature.p7x", bytesFileSource{data: sig}, false)
	if err != nil {
		return fmt.Errorf("msix: preparing signature: %w", err)
	}

	return writeZip(w, append(unsignedLayout, signatureEntry))
}

// writeZip streams the given entries into a new canonical-form zip written to w.
func writeZip(w io.Writer, entries []*compressedEntry) error {
	return writeCanonicalZip(w, entries)
}

func normalizePackagePath(p string) string {
	// Use forward slashes and clean the path.
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	return p
}
