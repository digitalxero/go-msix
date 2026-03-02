//go:build integration

package msix

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
)

// findMakemsixPack returns the path to a makemsix binary capable of packing, or skips the test.
func findMakemsixPack(t *testing.T) string {
	t.Helper()

	if p := os.Getenv("MAKEMSIX_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	if p, err := exec.LookPath("makemsix"); err == nil {
		return p
	}

	if root := os.Getenv("MSIX_PACKAGING_ROOT"); root != "" {
		p := filepath.Join(root, ".vs", "bin", "makemsix")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	t.Skip("makemsix not found: set MAKEMSIX_PATH, add makemsix to PATH, or set MSIX_PACKAGING_ROOT. " +
		"See https://github.com/Microsoft/msix-packaging for build instructions.")
	return ""
}

// findMakemsixUnpack returns the path to a makemsix binary capable of unpacking, or skips the test.
func findMakemsixUnpack(t *testing.T) string {
	t.Helper()

	if p := os.Getenv("MAKEMSIX_UNPACK_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Unpack uses the same binary as pack in most installations.
	return findMakemsixPack(t)
}

// extractZipContents unzips data into a map of filename -> uncompressed content.
func extractZipContents(t *testing.T, zipData []byte) map[string][]byte {
	t.Helper()

	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("extractZipContents: failed to open ZIP: %v", err)
	}

	files := make(map[string][]byte, len(r.File))
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("extractZipContents: failed to open %s: %v", f.Name, err)
		}
		var buf bytes.Buffer
		if _, err := buf.ReadFrom(rc); err != nil {
			rc.Close()
			t.Fatalf("extractZipContents: failed to read %s: %v", f.Name, err)
		}
		rc.Close()
		files[f.Name] = buf.Bytes()
	}
	return files
}

// compareFileInventory checks that both ZIPs contain the same set of file names.
func compareFileInventory(t *testing.T, goFiles, refFiles map[string][]byte) {
	t.Helper()

	goNames := sortedKeys(goFiles)
	refNames := sortedKeys(refFiles)

	// Files we expect to differ or be absent in one or the other.
	// makemsix may not produce AppxSignature.p7x for unsigned packages.
	goSet := toSet(goNames)
	refSet := toSet(refNames)

	for _, name := range goNames {
		if !refSet[name] {
			t.Errorf("file %q present in go-msix output but not in reference", name)
		}
	}
	for _, name := range refNames {
		if !goSet[name] {
			t.Errorf("file %q present in reference but not in go-msix output", name)
		}
	}
}

// comparePayloadContent verifies that uncompressed bytes match for each payload file.
func comparePayloadContent(t *testing.T, goFiles, refFiles map[string][]byte, payloadNames []string) {
	t.Helper()

	for _, name := range payloadNames {
		goData, ok1 := goFiles[name]
		refData, ok2 := refFiles[name]
		if !ok1 {
			t.Errorf("payload %q missing from go-msix output", name)
			continue
		}
		if !ok2 {
			t.Errorf("payload %q missing from reference output", name)
			continue
		}
		if !bytes.Equal(goData, refData) {
			t.Errorf("payload %q content mismatch: go-msix=%d bytes, ref=%d bytes",
				name, len(goData), len(refData))
		}
	}
}

// compareBlockMaps parses both block map XMLs and does semantic comparison.
func compareBlockMaps(t *testing.T, goBlockMap, refBlockMap []byte) {
	t.Helper()

	var goBM, refBM blockMapXML
	if err := xml.Unmarshal(goBlockMap, &goBM); err != nil {
		t.Fatalf("compareBlockMaps: failed to parse go-msix block map: %v", err)
	}
	if err := xml.Unmarshal(refBlockMap, &refBM); err != nil {
		t.Fatalf("compareBlockMaps: failed to parse reference block map: %v", err)
	}

	// Build maps by file name.
	goFileMap := make(map[string]blockMapFile, len(goBM.Files))
	for _, f := range goBM.Files {
		goFileMap[f.Name] = f
	}
	refFileMap := make(map[string]blockMapFile, len(refBM.Files))
	for _, f := range refBM.Files {
		refFileMap[f.Name] = f
	}

	// Same set of file names (order-independent).
	goNames := sortedKeys2(goFileMap)
	refNames := sortedKeys2(refFileMap)
	if len(goNames) != len(refNames) {
		t.Errorf("block map file count mismatch: go-msix=%d, ref=%d", len(goNames), len(refNames))
	}
	for _, name := range goNames {
		if _, ok := refFileMap[name]; !ok {
			t.Errorf("block map file %q in go-msix but not in reference", name)
		}
	}
	for _, name := range refNames {
		if _, ok := goFileMap[name]; !ok {
			t.Errorf("block map file %q in reference but not in go-msix", name)
		}
	}

	// For each common file, compare semantics.
	for name, goFile := range goFileMap {
		refFile, ok := refFileMap[name]
		if !ok {
			continue
		}

		// Same uncompressed size.
		if goFile.Size != refFile.Size {
			t.Errorf("block map %q: size mismatch: go=%d, ref=%d", name, goFile.Size, refFile.Size)
		}

		// Same number of blocks.
		if len(goFile.Blocks) != len(refFile.Blocks) {
			t.Errorf("block map %q: block count mismatch: go=%d, ref=%d",
				name, len(goFile.Blocks), len(refFile.Blocks))
			continue
		}

		// Same block hashes (SHA256 of uncompressed data — implementation-independent).
		for i := range goFile.Blocks {
			if goFile.Blocks[i].Hash != refFile.Blocks[i].Hash {
				t.Errorf("block map %q block %d: hash mismatch: go=%s, ref=%s",
					name, i, goFile.Blocks[i].Hash, refFile.Blocks[i].Hash)
			}
			// Note: LfhSize and block Size (compressed) may differ — that's OK.
		}
	}
}

// compareContentTypes parses both content types XMLs and does semantic comparison.
func compareContentTypes(t *testing.T, goCT, refCT []byte) {
	t.Helper()

	var goParsed, refParsed contentTypesXML
	if err := xml.Unmarshal(goCT, &goParsed); err != nil {
		t.Fatalf("compareContentTypes: failed to parse go-msix content types: %v", err)
	}
	if err := xml.Unmarshal(refCT, &refParsed); err != nil {
		t.Fatalf("compareContentTypes: failed to parse reference content types: %v", err)
	}

	// Compare Default entries (extension -> content type), order-independent.
	goDefaults := make(map[string]string, len(goParsed.Defaults))
	for _, d := range goParsed.Defaults {
		goDefaults[d.Extension] = d.ContentType
	}
	refDefaults := make(map[string]string, len(refParsed.Defaults))
	for _, d := range refParsed.Defaults {
		refDefaults[d.Extension] = d.ContentType
	}

	for ext, goMime := range goDefaults {
		refMime, ok := refDefaults[ext]
		if !ok {
			t.Errorf("content types: extension %q in go-msix but not in reference", ext)
			continue
		}
		if goMime != refMime {
			t.Errorf("content types: extension %q MIME mismatch: go=%q, ref=%q", ext, goMime, refMime)
		}
	}
	for ext := range refDefaults {
		if _, ok := goDefaults[ext]; !ok {
			t.Errorf("content types: extension %q in reference but not in go-msix", ext)
		}
	}

	// Compare Override entries (part name -> content type), order-independent.
	goOverrides := make(map[string]string, len(goParsed.Overrides))
	for _, o := range goParsed.Overrides {
		goOverrides[o.PartName] = o.ContentType
	}
	refOverrides := make(map[string]string, len(refParsed.Overrides))
	for _, o := range refParsed.Overrides {
		refOverrides[o.PartName] = o.ContentType
	}

	for pn, goMime := range goOverrides {
		refMime, ok := refOverrides[pn]
		if !ok {
			t.Errorf("content types: override %q in go-msix but not in reference", pn)
			continue
		}
		if goMime != refMime {
			t.Errorf("content types: override %q MIME mismatch: go=%q, ref=%q", pn, goMime, refMime)
		}
	}
	for pn := range refOverrides {
		if _, ok := goOverrides[pn]; !ok {
			t.Errorf("content types: override %q in reference but not in go-msix", pn)
		}
	}
}

// --- Test scenarios ---

func TestIntegration_SimplePackage(t *testing.T) {
	makemsixPack := findMakemsixPack(t)
	makemsixUnpack := findMakemsixUnpack(t)

	// Build with go-msix.
	b := NewBuilder()
	b.Manifest = simpleManifest()

	exeContent := []byte("MZ fake exe content for integration test")
	b.AddFileFromBytes("App.exe", exeContent)

	var goBuf bytes.Buffer
	if err := b.Build(&goBuf); err != nil {
		t.Fatalf("go-msix Build failed: %v", err)
	}
	goBytes := goBuf.Bytes()
	goFiles := extractZipContents(t, goBytes)

	// Extract our manifest to use as makemsix input.
	goManifest, ok := goFiles["AppxManifest.xml"]
	if !ok {
		t.Fatal("AppxManifest.xml not found in go-msix output")
	}

	// Create temp input dir for makemsix.
	inputDir := t.TempDir()
	writeTestFile(t, inputDir, "AppxManifest.xml", goManifest)
	writeTestFile(t, inputDir, "App.exe", exeContent)

	// Run makemsix pack.
	refPath := filepath.Join(t.TempDir(), "ref.msix")
	runMakemsix(t, makemsixPack, "pack", "-d", inputDir, "-p", refPath)

	refBytes, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatalf("failed to read reference package: %v", err)
	}
	refFiles := extractZipContents(t, refBytes)

	// Compare.
	compareFileInventory(t, goFiles, refFiles)
	comparePayloadContent(t, goFiles, refFiles, []string{"App.exe"})
	compareBlockMaps(t, goFiles["AppxBlockMap.xml"], refFiles["AppxBlockMap.xml"])
	compareContentTypes(t, goFiles["[Content_Types].xml"], refFiles["[Content_Types].xml"])

	// Validate our output is unpackable.
	verifyUnpack(t, makemsixUnpack, goBytes, map[string][]byte{
		"App.exe": exeContent,
	})
}

func TestIntegration_PackageWithSubdirectories(t *testing.T) {
	makemsixPack := findMakemsixPack(t)
	makemsixUnpack := findMakemsixUnpack(t)

	b := NewBuilder()
	b.Manifest = simpleManifest()

	payloads := map[string][]byte{
		"App.exe":           []byte("MZ fake exe"),
		"Assets/logo.png":   []byte("PNG fake logo data"),
		"Data/config.json":  []byte(`{"key": "value"}`),
		"readme.txt":        []byte("This is a readme file for testing."),
	}
	for path, data := range payloads {
		b.AddFileFromBytes(path, data)
	}

	var goBuf bytes.Buffer
	if err := b.Build(&goBuf); err != nil {
		t.Fatalf("go-msix Build failed: %v", err)
	}
	goBytes := goBuf.Bytes()
	goFiles := extractZipContents(t, goBytes)

	goManifest := goFiles["AppxManifest.xml"]

	// Create input dir with subdirectories.
	inputDir := t.TempDir()
	writeTestFile(t, inputDir, "AppxManifest.xml", goManifest)
	for path, data := range payloads {
		writeTestFile(t, inputDir, path, data)
	}

	refPath := filepath.Join(t.TempDir(), "ref.msix")
	runMakemsix(t, makemsixPack, "pack", "-d", inputDir, "-p", refPath)

	refBytes, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatalf("failed to read reference package: %v", err)
	}
	refFiles := extractZipContents(t, refBytes)

	payloadNames := sortedKeys(payloads)
	compareFileInventory(t, goFiles, refFiles)
	comparePayloadContent(t, goFiles, refFiles, payloadNames)
	compareBlockMaps(t, goFiles["AppxBlockMap.xml"], refFiles["AppxBlockMap.xml"])
	compareContentTypes(t, goFiles["[Content_Types].xml"], refFiles["[Content_Types].xml"])

	verifyUnpack(t, makemsixUnpack, goBytes, payloads)
}

func TestIntegration_LargeFileMultiBlock(t *testing.T) {
	makemsixPack := findMakemsixPack(t)
	makemsixUnpack := findMakemsixUnpack(t)

	b := NewBuilder()
	b.Manifest = simpleManifest()

	// Create a ~200KB file (3+ 64KB blocks).
	largeData := make([]byte, 200*1024)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	b.AddFileFromBytes("App.exe", []byte("MZ"))
	b.AddFileFromBytes("large.dat", largeData)

	var goBuf bytes.Buffer
	if err := b.Build(&goBuf); err != nil {
		t.Fatalf("go-msix Build failed: %v", err)
	}
	goBytes := goBuf.Bytes()
	goFiles := extractZipContents(t, goBytes)

	goManifest := goFiles["AppxManifest.xml"]

	inputDir := t.TempDir()
	writeTestFile(t, inputDir, "AppxManifest.xml", goManifest)
	writeTestFile(t, inputDir, "App.exe", []byte("MZ"))
	writeTestFile(t, inputDir, "large.dat", largeData)

	refPath := filepath.Join(t.TempDir(), "ref.msix")
	runMakemsix(t, makemsixPack, "pack", "-d", inputDir, "-p", refPath)

	refBytes, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatalf("failed to read reference package: %v", err)
	}
	refFiles := extractZipContents(t, refBytes)

	compareFileInventory(t, goFiles, refFiles)
	comparePayloadContent(t, goFiles, refFiles, []string{"App.exe", "large.dat"})
	compareBlockMaps(t, goFiles["AppxBlockMap.xml"], refFiles["AppxBlockMap.xml"])
	compareContentTypes(t, goFiles["[Content_Types].xml"], refFiles["[Content_Types].xml"])

	verifyUnpack(t, makemsixUnpack, goBytes, map[string][]byte{
		"App.exe":   []byte("MZ"),
		"large.dat": largeData,
	})
}

func TestIntegration_UnpackValidation(t *testing.T) {
	makemsixUnpack := findMakemsixUnpack(t)

	b := NewBuilder()
	b.Manifest = simpleManifest()

	payloads := map[string][]byte{
		"App.exe":          []byte("MZ fake exe for unpack test"),
		"Assets/icon.png":  []byte("PNG icon data"),
		"lib/helper.dll":   []byte("MZ DLL fake"),
		"config.json":      []byte(`{"setting": true}`),
	}
	for path, data := range payloads {
		b.AddFileFromBytes(path, data)
	}

	var goBuf bytes.Buffer
	if err := b.Build(&goBuf); err != nil {
		t.Fatalf("go-msix Build failed: %v", err)
	}

	verifyUnpack(t, makemsixUnpack, goBuf.Bytes(), payloads)
}

// --- Helpers ---

// simpleManifest returns a minimal valid manifest for integration testing.
func simpleManifest() Manifest {
	return Manifest{
		Identity: Identity{
			Name:                  "Integration.TestApp",
			Version:               "1.0.0.0",
			Publisher:             "CN=IntegrationTest",
			ProcessorArchitecture: "x64",
		},
		Properties: Properties{
			DisplayName:         "Integration Test App",
			PublisherDisplayName: "Integration Test",
			Logo:                "Assets/logo.png",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID:         "App",
				Executable: "App.exe",
				EntryPoint: "Windows.FullTrustApplication",
				VisualElements: VisualElements{
					DisplayName:       "Integration Test App",
					Description:       "Integration test application",
					BackgroundColor:   "transparent",
					Square150x150Logo: "Assets/logo.png",
					Square44x44Logo:   "Assets/logo.png",
				},
			},
		},
		Capabilities: Capabilities{
			Restricted: []RestrictedCapability{{Name: "runFullTrust"}},
		},
	}
}

// writeTestFile creates a file (with parent directories) in the given base directory.
func writeTestFile(t *testing.T, baseDir, relPath string, data []byte) {
	t.Helper()
	fullPath := filepath.Join(baseDir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("failed to create directory for %s: %v", relPath, err)
	}
	if err := os.WriteFile(fullPath, data, 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", relPath, err)
	}
}

// runMakemsix runs makemsix with the given arguments, failing the test on error.
func runMakemsix(t *testing.T, binary string, args ...string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("makemsix %v failed: %v\nOutput: %s", args, err, output)
	}
}

// verifyUnpack writes goBytes to a temp file, runs makemsix unpack, and verifies extracted files.
func verifyUnpack(t *testing.T, makemsixUnpack string, goBytes []byte, expectedPayloads map[string][]byte) {
	t.Helper()

	// Write our package to a temp file.
	tmpFile := filepath.Join(t.TempDir(), "test.msix")
	if err := os.WriteFile(tmpFile, goBytes, 0o644); err != nil {
		t.Fatalf("failed to write temp msix: %v", err)
	}

	// Unpack (with -ss to skip signature enforcement for unsigned packages).
	outDir := filepath.Join(t.TempDir(), "unpacked")
	runMakemsix(t, makemsixUnpack, "unpack", "-ss", "-p", tmpFile, "-d", outDir)

	// Verify payload files were extracted with correct content.
	for name, expectedData := range expectedPayloads {
		extractedPath := filepath.Join(outDir, filepath.FromSlash(name))
		data, err := os.ReadFile(extractedPath)
		if err != nil {
			t.Errorf("unpack: failed to read extracted %s: %v", name, err)
			continue
		}
		if !bytes.Equal(data, expectedData) {
			t.Errorf("unpack: %s content mismatch: extracted=%d bytes, expected=%d bytes",
				name, len(data), len(expectedData))
		}
	}

	// Verify metadata files were extracted.
	// Note: makemsix does not extract [Content_Types].xml to disk — it's consumed internally.
	for _, meta := range []string{"AppxManifest.xml", "AppxBlockMap.xml"} {
		metaPath := filepath.Join(outDir, meta)
		if _, err := os.Stat(metaPath); err != nil {
			t.Errorf("unpack: metadata file %s not found: %v", meta, err)
		}
	}
}

// --- Utility functions ---

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys2(m map[string]blockMapFile) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func toSet(keys []string) map[string]bool {
	s := make(map[string]bool, len(keys))
	for _, k := range keys {
		s[k] = true
	}
	return s
}

