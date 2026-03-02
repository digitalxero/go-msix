package msix

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestBuilder_RoundTrip(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity: Identity{
			Name: "Test.App", Version: "1.0.0.0",
			Publisher: "CN=Test", ProcessorArchitecture: "x64",
		},
		Properties: Properties{
			DisplayName: "Test App", PublisherDisplayName: "Test",
			Logo: "Assets/logo.png",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test App", BackgroundColor: "#464646",
					Square150x150Logo: "Assets/150.png", Square44x44Logo: "Assets/44.png",
				},
			},
		},
	}

	b.AddFileFromBytes("App.exe", []byte("MZ fake exe content"))
	b.AddFileFromBytes("Assets/logo.png", []byte("PNG fake"))
	b.AddFileFromBytes("Assets/150.png", []byte("PNG fake 150"))
	b.AddFileFromBytes("Assets/44.png", []byte("PNG fake 44"))

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	// Read back the ZIP.
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Check expected files are present.
	expectedFiles := map[string]bool{
		"App.exe":              false,
		"Assets/logo.png":      false,
		"Assets/150.png":       false,
		"Assets/44.png":        false,
		"AppxManifest.xml":     false,
		"AppxBlockMap.xml":     false,
		"[Content_Types].xml":  false,
	}

	for _, f := range reader.File {
		if _, ok := expectedFiles[f.Name]; ok {
			expectedFiles[f.Name] = true
		}
	}

	for name, found := range expectedFiles {
		if !found {
			t.Errorf("expected file %s not found in package", name)
		}
	}
}

func TestBuilder_ManifestContent(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity: Identity{
			Name: "MyCompany.MyApp", Version: "2.0.0.0",
			Publisher: "CN=MyCompany", ProcessorArchitecture: "x64",
		},
		Properties: Properties{
			DisplayName: "My App", PublisherDisplayName: "My Company",
			Logo: "Assets/logo.png",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources:    []Resource{{Language: "en-us"}},
		Capabilities: Capabilities{
			Restricted: []RestrictedCapability{{Name: "runFullTrust"}},
		},
		Applications: []Application{
			{
				ID: "App", Executable: "MyApp.exe",
				VisualElements: VisualElements{
					DisplayName: "My App", BackgroundColor: "#464646",
					Square150x150Logo: "Assets/150.png", Square44x44Logo: "Assets/44.png",
				},
			},
		},
	}

	b.AddFileFromBytes("MyApp.exe", []byte("MZ"))

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Find and read AppxManifest.xml.
	var manifestContent string
	for _, f := range reader.File {
		if f.Name == "AppxManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			manifestContent = string(data)
			break
		}
	}

	if manifestContent == "" {
		t.Fatal("AppxManifest.xml not found or empty")
	}

	if !strings.Contains(manifestContent, `Name="MyCompany.MyApp"`) {
		t.Fatal("manifest missing app name")
	}
	if !strings.Contains(manifestContent, `rescap:Capability Name="runFullTrust"`) {
		t.Fatal("manifest missing restricted capability")
	}
}

func TestBuilder_BlockMapIntegrity(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity: Identity{
			Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test",
		},
		Properties: Properties{
			DisplayName: "Test", PublisherDisplayName: "Test",
		},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test", BackgroundColor: "#000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
			},
		},
	}

	fileContent := []byte("test file content for block map verification")
	b.AddFileFromBytes("App.exe", fileContent)

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	// Read block map.
	var blockMapData []byte
	for _, f := range reader.File {
		if f.Name == "AppxBlockMap.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			blockMapData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}

	if blockMapData == nil {
		t.Fatal("AppxBlockMap.xml not found")
	}

	// Parse block map.
	var bm blockMapXML
	if err := xml.Unmarshal(blockMapData, &bm); err != nil {
		t.Fatal(err)
	}

	// Find the App.exe entry and verify hash.
	for _, file := range bm.Files {
		if file.Name == "App.exe" {
			if len(file.Blocks) != 1 {
				t.Fatalf("expected 1 block for App.exe, got %d", len(file.Blocks))
			}

			expectedHash := sha256.Sum256(fileContent)
			expectedB64 := base64.StdEncoding.EncodeToString(expectedHash[:])
			if file.Blocks[0].Hash != expectedB64 {
				t.Fatalf("block hash mismatch for App.exe: got %s, expected %s",
					file.Blocks[0].Hash, expectedB64)
			}
			return
		}
	}

	t.Fatal("App.exe not found in block map")
}

func TestBuilder_AddFileFromReader(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity:   Identity{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: Properties{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test", BackgroundColor: "#000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
			},
		},
	}

	content := "reader content"
	if err := b.AddFileFromReader("data.txt", strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	b.AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range reader.File {
		if f.Name == "data.txt" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != content {
				t.Fatalf("content mismatch: got %q, expected %q", string(data), content)
			}
			return
		}
	}

	t.Fatal("data.txt not found in package")
}

func TestBuilder_SignedPackage(t *testing.T) {
	// Generate self-signed cert.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	b := NewBuilder()

	b.Manifest = Manifest{
		Identity:   Identity{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: Properties{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test", BackgroundColor: "#000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
			},
		},
	}

	b.AddFileFromBytes("App.exe", []byte("MZ"))
	b.SignOptions = &SignOptions{
		Certificate: cert,
		PrivateKey:  key,
	}

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	// Read back and verify signature file exists.
	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	foundSig := false
	for _, f := range reader.File {
		if f.Name == "AppxSignature.p7x" {
			foundSig = true

			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			sigData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}

			// Verify PKCX header.
			if !bytes.HasPrefix(sigData, p7xMagic) {
				t.Fatal("missing PKCX header in signature")
			}
			break
		}
	}

	if !foundSig {
		t.Fatal("AppxSignature.p7x not found in signed package")
	}
}

func TestBuilder_EmptyFile(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity:   Identity{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: Properties{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test", BackgroundColor: "#000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
			},
		},
	}

	b.AddFileFromBytes("App.exe", []byte("MZ"))
	b.AddFileFromBytes("empty.txt", nil)

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range reader.File {
		if f.Name == "empty.txt" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != 0 {
				t.Fatalf("expected empty file, got %d bytes", len(data))
			}
			return
		}
	}

	t.Fatal("empty.txt not found")
}

func TestNormalizePackagePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"test.txt", "test.txt"},
		{"/test.txt", "test.txt"},
		{"dir/file.txt", "dir/file.txt"},
		{"dir\\file.txt", "dir/file.txt"},
	}

	for _, tt := range tests {
		got := normalizePackagePath(tt.input)
		if got != tt.want {
			t.Errorf("normalizePackagePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBuilder_ContentTypesPresent(t *testing.T) {
	b := NewBuilder()

	b.Manifest = Manifest{
		Identity:   Identity{Name: "Test.App", Version: "1.0.0.0", Publisher: "CN=Test"},
		Properties: Properties{DisplayName: "Test", PublisherDisplayName: "Test"},
		Dependencies: Dependencies{
			TargetDeviceFamilies: []TargetDeviceFamily{
				{Name: "Windows.Desktop", MinVersion: "10.0.17763.0", MaxVersionTested: "10.0.22621.0"},
			},
		},
		Resources: []Resource{{Language: "en-us"}},
		Applications: []Application{
			{
				ID: "App", Executable: "App.exe",
				VisualElements: VisualElements{
					DisplayName: "Test", BackgroundColor: "#000",
					Square150x150Logo: "a.png", Square44x44Logo: "b.png",
				},
			},
		},
	}

	b.AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	if err := b.Build(&buf); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range reader.File {
		if f.Name == "[Content_Types].xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}

			s := string(data)
			if !strings.Contains(s, contentTypesNamespace) {
				t.Fatal("missing content types namespace")
			}
			if !strings.Contains(s, "AppxBlockMap") {
				t.Fatal("missing AppxBlockMap override")
			}
			return
		}
	}

	t.Fatal("[Content_Types].xml not found")
}
