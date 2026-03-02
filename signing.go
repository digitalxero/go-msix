package msix

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"os"

	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// APPX digest tags.
const (
	tagAXPC uint32 = 0x41585043 // Hash of local file headers + data
	tagAXCD uint32 = 0x41584344 // Hash of central directory
	tagAXCT uint32 = 0x41584354 // Hash of [Content_Types].xml
	tagAXBM uint32 = 0x4158424D // Hash of AppxBlockMap.xml
	tagAXCI uint32 = 0x41584349 // Hash of CodeIntegrity.cat
)

// P7X magic header.
var p7xMagic = []byte{0x50, 0x4B, 0x43, 0x58} // "PKCX"

// SPC Indirect Data OID: 1.3.6.1.4.1.311.2.1.4
var oidSpcIndirectData = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}

// OID for SHA256: 2.16.840.1.101.3.4.2.1
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// SPC Sipinfo OID: 1.3.6.1.4.1.311.2.1.30
var oidSpcSipInfo = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 30}

// digestInfo holds the algorithm and digest value for SpcIndirectDataContent.
type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// spcIndirectDataContent is the ASN.1 structure embedded in the CMS SignedData.
type spcIndirectDataContent struct {
	Data    spcAttributeTypeAndValue
	MessageDigest digestInfo
}

type spcAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value spcSipInfo `asn1:"tag:0,explicit"`
}

// spcSipInfo holds the APPX digest blob.
type spcSipInfo struct {
	Version    int
	SipGUID    []byte
	Reserved1  int
	Reserved2  int
	Reserved3  int
	Reserved4  int
	Reserved5  int
	AppxDigest []byte
}

// LoadPFX loads a PFX/P12 file and returns the certificate, private key, and any chain certificates.
func LoadPFX(path string, password string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msix: reading PFX: %w", err)
	}

	key, cert, chain, err := gopkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("msix: decoding PFX: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("msix: PFX private key does not implement crypto.Signer")
	}

	return cert, signer, chain, nil
}

// hashBytes computes SHA256 of the input.
func hashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// buildDigestBlob creates the 184-byte APPX digest blob.
// Format: "APPX" (4 bytes) + 5 entries of (4-byte tag + 32-byte hash) = 4 + 5*36 = 184 bytes.
func buildDigestBlob(axpc, axcd, axct, axbm, axci [32]byte) []byte {
	blob := make([]byte, 184)
	copy(blob[0:4], []byte("APPX"))

	entries := []struct {
		tag  uint32
		hash [32]byte
	}{
		{tagAXPC, axpc},
		{tagAXCD, axcd},
		{tagAXCT, axct},
		{tagAXBM, axbm},
		{tagAXCI, axci},
	}

	offset := 4
	for _, e := range entries {
		binary.LittleEndian.PutUint32(blob[offset:offset+4], e.tag)
		copy(blob[offset+4:offset+36], e.hash[:])
		offset += 36
	}

	return blob
}

// createSignature creates the AppxSignature.p7x content.
func createSignature(axpc, axcd, axct, axbm, axci [32]byte, opts *SignOptions) ([]byte, error) {
	digestBlob := buildDigestBlob(axpc, axcd, axct, axbm, axci)

	// Hash the digest blob for the SpcIndirectDataContent.
	digestHash := sha256.Sum256(digestBlob)

	// Build the SpcIndirectDataContent.
	// The SipGUID for APPX is {4BDFC50A-28E2-4F10-A251-4181E087C42C}
	sipGUID := []byte{
		0x0A, 0xC5, 0xDF, 0x4B,
		0xE2, 0x28,
		0x10, 0x4F,
		0xA2, 0x51,
		0x41, 0x81, 0xE0, 0x87, 0xC4, 0x2C,
	}

	indirect := spcIndirectDataContent{
		Data: spcAttributeTypeAndValue{
			Type: oidSpcSipInfo,
			Value: spcSipInfo{
				Version:    0x01000000,
				SipGUID:    sipGUID,
				AppxDigest: digestBlob,
			},
		},
		MessageDigest: digestInfo{
			Algorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			Digest: digestHash[:],
		},
	}

	indirectBytes, err := asn1.Marshal(indirect)
	if err != nil {
		return nil, fmt.Errorf("msix: marshaling SpcIndirectDataContent: %w", err)
	}

	// Create PKCS7 SignedData.
	signedData, err := pkcs7.NewSignedData(indirectBytes)
	if err != nil {
		return nil, fmt.Errorf("msix: creating SignedData: %w", err)
	}

	// Set the content type to SPC_INDIRECT_DATA_OBJID.
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signedData.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSA)

	// Add the signer.
	if err := signedData.AddSigner(opts.Certificate, opts.PrivateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("msix: adding signer: %w", err)
	}

	// Add chain certificates.
	for _, cert := range opts.CertChain {
		signedData.AddCertificate(cert)
	}

	// Finalize.
	cms, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("msix: finishing SignedData: %w", err)
	}

	// Prepend PKCX header.
	p7x := make([]byte, 4+len(cms))
	copy(p7x[0:4], p7xMagic)
	copy(p7x[4:], cms)

	return p7x, nil
}
