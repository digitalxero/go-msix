package msix

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"os"

	"go.mozilla.org/pkcs7"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// APPX digest tags.
const (
	tagAXPC = "AXPC" // Hash of local file headers + data
	tagAXCD = "AXCD" // Hash of central directory + end records
	tagAXCT = "AXCT" // Hash of [Content_Types].xml
	tagAXBM = "AXBM" // Hash of AppxBlockMap.xml
	tagAXCI = "AXCI" // Hash of CodeIntegrity.cat
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
	Data          spcAttributeTypeAndValue
	MessageDigest digestInfo
}

type spcAttributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value spcSipInfo
}

// spcSipInfo identifies the APPX subject interface package.
type spcSipInfo struct {
	Version   int
	SipGUID   []byte
	Reserved1 int
	Reserved2 int
	Reserved3 int
	Reserved4 int
	Reserved5 int
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

// buildDigestBlob creates the APPX digest table. AXCI is present only when
// the package contains AppxMetadata/CodeIntegrity.cat.
func buildDigestBlob(axpc, axcd, axct, axbm [32]byte, axci *[32]byte) []byte {
	type entry struct {
		tag  string
		hash [32]byte
	}
	entries := []entry{
		{tagAXPC, axpc},
		{tagAXCD, axcd},
		{tagAXCT, axct},
		{tagAXBM, axbm},
	}
	if axci != nil {
		entries = append(entries, entry{tagAXCI, *axci})
	}

	blob := make([]byte, 4+36*len(entries))
	copy(blob, "APPX")
	offset := 4
	for _, e := range entries {
		copy(blob[offset:offset+4], e.tag)
		copy(blob[offset+4:offset+36], e.hash[:])
		offset += 36
	}

	return blob
}

// createSignature creates the AppxSignature.p7x content.
func createSignature(axpc, axcd, axct, axbm [32]byte, axci *[32]byte, creds *signingCreds) ([]byte, error) {
	digestBlob := buildDigestBlob(axpc, axcd, axct, axbm, axci)

	// Build the SpcIndirectDataContent.
	// APPX SIP identifier in the byte order used by SignTool.
	sipGUID := []byte{
		0x4B, 0xDF, 0xC5, 0x0A,
		0x07, 0xCE,
		0xE2, 0x4D,
		0xB7, 0x6E,
		0x23, 0xC8, 0x39, 0xA0, 0x9F, 0xD1,
	}

	indirect := spcIndirectDataContent{
		Data: spcAttributeTypeAndValue{
			Type: oidSpcSipInfo,
			Value: spcSipInfo{
				Version: 0x01010000,
				SipGUID: sipGUID,
			},
		},
		MessageDigest: digestInfo{
			Algorithm: algorithmIdentifier{
				Algorithm:  oidSHA256,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			Digest: digestBlob,
		},
	}

	indirectBytes, err := asn1.Marshal(indirect)
	if err != nil {
		return nil, fmt.Errorf("msix: marshaling SpcIndirectDataContent: %w", err)
	}

	// Authenticode hashes the sequence contents, excluding its outer tag/length,
	// but embeds the complete sequence rather than a CMS octet string.
	var indirectContent asn1.RawValue
	if _, err := asn1.Unmarshal(indirectBytes, &indirectContent); err != nil {
		return nil, fmt.Errorf("msix: decoding SpcIndirectDataContent: %w", err)
	}
	signedData, err := pkcs7.NewSignedData(indirectContent.Bytes)
	if err != nil {
		return nil, fmt.Errorf("msix: creating SignedData: %w", err)
	}

	contentInfo := &signedData.GetSignedData().ContentInfo
	contentInfo.ContentType = oidSpcIndirectData
	contentInfo.Content = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: indirectBytes}
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// Add the signer.
	if err := signedData.AddSigner(creds.cert, creds.key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("msix: adding signer: %w", err)
	}

	// Add chain certificates.
	for _, cert := range creds.chain {
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
