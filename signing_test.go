package msix

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestBuildDigestBlob(t *testing.T) {
	axpc := sha256.Sum256([]byte("axpc"))
	axcd := sha256.Sum256([]byte("axcd"))
	axct := sha256.Sum256([]byte("axct"))
	axbm := sha256.Sum256([]byte("axbm"))
	axci := sha256.Sum256([]byte("axci"))

	blob := buildDigestBlob(axpc, axcd, axct, axbm, axci)

	// Check total size.
	if len(blob) != 184 {
		t.Fatalf("expected 184 bytes, got %d", len(blob))
	}

	// Check APPX header.
	if string(blob[0:4]) != "APPX" {
		t.Fatal("missing APPX header")
	}

	// Check tags.
	tags := []uint32{tagAXPC, tagAXCD, tagAXCT, tagAXBM, tagAXCI}
	hashes := [][32]byte{axpc, axcd, axct, axbm, axci}

	offset := 4
	for i, tag := range tags {
		gotTag := binary.LittleEndian.Uint32(blob[offset : offset+4])
		if gotTag != tag {
			t.Fatalf("tag %d: expected 0x%X, got 0x%X", i, tag, gotTag)
		}
		var gotHash [32]byte
		copy(gotHash[:], blob[offset+4:offset+36])
		if gotHash != hashes[i] {
			t.Fatalf("hash %d mismatch", i)
		}
		offset += 36
	}
}

func TestHashBytes(t *testing.T) {
	data := []byte("test data")
	expected := sha256.Sum256(data)
	got := hashBytes(data)
	if got != expected {
		t.Fatal("hash mismatch")
	}
}

func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "TestCompany",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
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

	return cert, key
}

func TestCreateSignature(t *testing.T) {
	cert, key := generateSelfSignedCert(t)

	axpc := sha256.Sum256([]byte("axpc"))
	axcd := sha256.Sum256([]byte("axcd"))
	axct := sha256.Sum256([]byte("axct"))
	axbm := sha256.Sum256([]byte("axbm"))
	var axci [32]byte

	opts := &SignOptions{
		Certificate: cert,
		PrivateKey:  key,
	}

	sig, err := createSignature(axpc, axcd, axct, axbm, axci, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Check PKCX header.
	if !bytes.HasPrefix(sig, p7xMagic) {
		t.Fatal("missing PKCX header")
	}

	// Minimum size: 4 bytes header + some CMS data.
	if len(sig) < 100 {
		t.Fatalf("signature too small: %d bytes", len(sig))
	}
}

func TestP7xMagic(t *testing.T) {
	expected := []byte{0x50, 0x4B, 0x43, 0x58}
	if !bytes.Equal(p7xMagic, expected) {
		t.Fatal("p7x magic mismatch")
	}
}
