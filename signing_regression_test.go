package msix

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
)

func TestSignedPackageAuthenticode(t *testing.T) {
	cert, key := testSelfSignedCert(t)
	var buf bytes.Buffer
	require.NoError(t, goldenBaseBuilder().
		AddFileFromBytes("App.exe", []byte("MZ")).
		WithSigning(NewSigning().WithCertificate(cert).WithPrivateKey(key).Build()).
		Build(context.Background(), &buf))

	sig := unzipAll(t, buf.Bytes())["AppxSignature.p7x"]
	blob := appxSignatureDigests(t, sig)
	require.Len(t, blob, 148, "a package without CodeIntegrity.cat has four digests")
	require.Equal(t, "APPX", string(blob[:4]))
	for i, tag := range []string{"AXPC", "AXCD", "AXCT", "AXBM"} {
		require.Equal(t, tag, string(blob[4+i*36:8+i*36]))
	}

	p7, err := pkcs7.Parse(sig[4:])
	require.NoError(t, err)
	p7.Content[len(p7.Content)-1] ^= 1
	require.Error(t, p7.Verify(), "changed digest content must invalidate the signature")
}

func TestSignedPackageDigests(t *testing.T) {
	for _, catalog := range []bool{false, true} {
		name := "without catalog"
		if catalog {
			name = "with catalog"
		}
		t.Run(name, func(t *testing.T) {
			cert, key := testSelfSignedCert(t)
			b := goldenBaseBuilder().
				AddFileFromBytes("App.exe", goldenPattern(200*1024)).
				WithSigning(NewSigning().WithCertificate(cert).WithPrivateKey(key).Build())
			if catalog {
				b.AddFileFromBytes("AppxMetadata/CodeIntegrity.cat", goldenPattern(100*1024))
			}
			var buf bytes.Buffer
			require.NoError(t, b.Build(context.Background(), &buf))

			parts := unzipAll(t, buf.Bytes())
			blob := appxSignatureDigests(t, parts["AppxSignature.p7x"])
			r, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
			require.NoError(t, err)
			require.Equal(t, "AppxSignature.p7x", r.File[len(r.File)-1].Name)

			// Remove only the signature. Copy preserves the compressed bytes and
			// recreates the central directory and EOCD with unsigned offsets/counts.
			var unsigned bytes.Buffer
			zw := zip.NewWriter(&unsigned)
			for _, f := range r.File {
				if f.Name != "AppxSignature.p7x" {
					require.NoError(t, zw.Copy(f))
				}
			}
			require.NoError(t, zw.Close())
			data := unsigned.Bytes()
			end := data[len(data)-22:]
			require.Equal(t, []byte("PK\x05\x06"), end[:4])
			cdOffset := binary.LittleEndian.Uint32(end[16:20])
			require.Equal(t, buf.Bytes()[:cdOffset], data[:cdOffset], "signed file records must not change")

			expected := map[string][32]byte{
				"AXPC": sha256.Sum256(data[:cdOffset]),
				"AXCD": sha256.Sum256(data[cdOffset:]),
				"AXCT": sha256.Sum256(parts["[Content_Types].xml"]),
				"AXBM": sha256.Sum256(parts["AppxBlockMap.xml"]),
			}
			if catalog {
				expected["AXCI"] = sha256.Sum256(parts["AppxMetadata/CodeIntegrity.cat"])
			}
			require.Len(t, blob, 4+36*len(expected))
			for offset := 4; offset < len(blob); offset += 36 {
				tag := string(blob[offset : offset+4])
				digest, ok := expected[tag]
				require.True(t, ok, "unexpected or repeated digest %q", tag)
				require.Equal(t, digest[:], blob[offset+4:offset+36], "%s", tag)
				delete(expected, tag)
			}
			require.Empty(t, expected)
		})
	}
}

func appxSignatureDigests(t *testing.T, sig []byte) []byte {
	t.Helper()
	require.Greater(t, len(sig), 4)
	require.Equal(t, []byte("PKCX"), sig[:4])

	p7, err := pkcs7.Parse(sig[4:])
	require.NoError(t, err)
	require.NoError(t, p7.Verify())
	var contentType asn1.ObjectIdentifier
	require.NoError(t, p7.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType))
	require.Equal(t, "1.3.6.1.4.1.311.2.1.4", contentType.String())

	type contentInfo struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue `asn1:"explicit,tag:0"`
	}
	var outer contentInfo
	rest, err := asn1.Unmarshal(sig[4:], &outer)
	require.NoError(t, err)
	require.Empty(t, rest)
	var signed struct {
		Version    int
		Algorithms asn1.RawValue
		Content    contentInfo
	}
	_, err = asn1.Unmarshal(outer.Content.Bytes, &signed)
	require.NoError(t, err)
	require.Equal(t, "1.3.6.1.4.1.311.2.1.4", signed.Content.Type.String())

	var indirect struct {
		Data struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		MessageDigest struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
	}
	rest, err = asn1.Unmarshal(signed.Content.Content.Bytes, &indirect)
	require.NoError(t, err, "Authenticode content must be a sequence, not an octet string")
	require.Empty(t, rest)
	require.Equal(t, "1.3.6.1.4.1.311.2.1.30", indirect.Data.Type.String())
	// SIP metadata from Microsoft's TestAppxPackage_x64.appx.
	require.Equal(t,
		"302702040101000004104bdfc50a07cee24db76e23c839a09fd1020100020100020100020100020100",
		hex.EncodeToString(indirect.Data.Value.FullBytes))
	require.Equal(t, "2.16.840.1.101.3.4.2.1", indirect.MessageDigest.Algorithm.Algorithm.String())
	return indirect.MessageDigest.Digest
}
