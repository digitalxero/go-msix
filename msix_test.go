package msix_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	msix "go.digitalxero.dev/go-msix"
)

// stdManifestBuilder returns a Builder with a complete, valid manifest (no files).
func stdManifestBuilder() msix.Builder {
	return msix.NewBuilder().
		WithIdentity(msix.NewIdentity().
			WithName("Test.App").WithVersion("1.0.0.0").
			WithPublisher("CN=Test").WithProcessorArchitecture("x64").Build()).
		WithProperties(msix.NewProperties().
			WithDisplayName("Test App").WithPublisherDisplayName("Test").
			WithLogo("Assets/logo.png").Build()).
		WithDependencies(msix.NewDependencies().
			AddTargetDeviceFamily("Windows.Desktop", "10.0.17763.0", "10.0.22621.0").Build()).
		AddResource(msix.NewResource().WithLanguage("en-us").Build()).
		WithCapabilities(msix.NewCapabilities().AddRestricted("runFullTrust").Build()).
		AddApplication(msix.NewApplication().
			WithID("App").WithExecutable("App.exe").
			WithVisualElements(msix.NewVisualElements().
				WithDisplayName("Test App").WithDescription("Test application").WithBackgroundColor("#464646").
				WithSquare150x150Logo("Assets/150.png").WithSquare44x44Logo("Assets/44.png").
				Build()).
			Build())
}

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	out := make(map[string][]byte, len(r.File))
	for _, f := range r.File {
		rc, err := f.Open()
		require.NoError(t, err)
		b, err := io.ReadAll(rc)
		rc.Close()
		require.NoError(t, err)
		out[f.Name] = b
	}
	return out
}

func selfSignedCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func TestBuilder_RoundTrip(t *testing.T) {
	b := stdManifestBuilder().
		AddFileFromBytes("App.exe", []byte("MZ fake exe content")).
		AddFileFromBytes("Assets/logo.png", []byte("PNG fake")).
		AddFileFromBytes("Assets/150.png", []byte("PNG fake 150")).
		AddFileFromBytes("Assets/44.png", []byte("PNG fake 44"))

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	for _, name := range []string{
		"App.exe", "Assets/logo.png", "Assets/150.png", "Assets/44.png",
		"AppxManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml",
	} {
		assert.Contains(t, files, name, "expected file %s in package", name)
	}
}

func TestBuilder_ManifestContent(t *testing.T) {
	b := stdManifestBuilder().AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	manifest := string(files["AppxManifest.xml"])
	assert.Contains(t, manifest, `Name="Test.App"`)
	assert.Contains(t, manifest, `rescap:Capability Name="runFullTrust"`)
}

func TestBuilder_AddFileFromReader(t *testing.T) {
	content := "reader content"
	b := stdManifestBuilder().
		AddFileFromReader("data.txt", strings.NewReader(content)).
		AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	require.Contains(t, files, "data.txt")
	assert.Equal(t, content, string(files["data.txt"]))
}

func TestBuilder_EmptyFile(t *testing.T) {
	b := stdManifestBuilder().
		AddFileFromBytes("App.exe", []byte("MZ")).
		AddFileFromBytes("empty.txt", nil)

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	require.Contains(t, files, "empty.txt")
	assert.Empty(t, files["empty.txt"])
}

func TestBuilder_SignedPackage(t *testing.T) {
	cert, key := selfSignedCert(t)
	b := stdManifestBuilder().
		AddFileFromBytes("App.exe", []byte("MZ")).
		WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(key).Build())

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	require.Contains(t, files, "AppxSignature.p7x")
	assert.True(t, bytes.HasPrefix(files["AppxSignature.p7x"], []byte{0x50, 0x4B, 0x43, 0x58}),
		"missing PKCX header in signature")
}

func TestBuilder_ContentTypesPresent(t *testing.T) {
	b := stdManifestBuilder().AddFileFromBytes("App.exe", []byte("MZ"))

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	ct := string(files["[Content_Types].xml"])
	assert.Contains(t, ct, "http://schemas.openxmlformats.org/package/2006/content-types")
	assert.Contains(t, ct, "AppxBlockMap")
}

func TestBuilder_BlockMapIntegrity(t *testing.T) {
	content := []byte("test file content for block map verification")
	b := stdManifestBuilder().AddFileFromBytes("App.exe", content)

	var buf bytes.Buffer
	require.NoError(t, b.Build(context.Background(), &buf))

	files := unzip(t, buf.Bytes())
	require.Contains(t, files, "AppxBlockMap.xml")

	var bm struct {
		Files []struct {
			Name   string `xml:"Name,attr"`
			Blocks []struct {
				Hash string `xml:"Hash,attr"`
			} `xml:"Block"`
		} `xml:"File"`
	}
	require.NoError(t, xml.Unmarshal(files["AppxBlockMap.xml"], &bm))

	expected := sha256.Sum256(content)
	expectedB64 := base64.StdEncoding.EncodeToString(expected[:])
	found := false
	for _, f := range bm.Files {
		if f.Name == "App.exe" {
			require.Len(t, f.Blocks, 1)
			assert.Equal(t, expectedB64, f.Blocks[0].Hash)
			found = true
		}
	}
	assert.True(t, found, "App.exe not found in block map")
}

func TestBuilder_ValidationError(t *testing.T) {
	b := msix.NewBuilder().AddFileFromBytes("App.exe", []byte("MZ"))
	err := b.Build(context.Background(), &bytes.Buffer{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity name is required")
}
