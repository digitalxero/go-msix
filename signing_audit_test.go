package msix_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msix "go.digitalxero.dev/go-msix"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
)

func auditCert(t *testing.T, key crypto.Signer, raw []byte) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(42), RawSubject: raw, Subject: pkix.Name{CommonName: "Test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
func auditSubjects() []struct {
	name      string
	rdns      pkix.RDNSequence
	publisher string
} {
	return []struct {
		name      string
		rdns      pkix.RDNSequence
		publisher string
	}{
		{"ordered", pkix.Name{Country: []string{"US"}, Province: []string{"Washington"}, Organization: []string{"TestCo"}, CommonName: "Test"}.ToRDNSequence(), "CN=Test, O=TestCo, S=Washington, C=US"},
		{"repeated", pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "First"}}, {{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}}, {{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "Last"}}}, "CN=Last, O=Org, CN=First"},
		{"quoted", pkix.Name{CommonName: ` Test, + = " \ < > # ; `}.ToRDNSequence(), `CN=" Test, + = "" \ < > # ; "`},
		{"unknown OID", pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "Custom"}}}, "OID.1.2.3.4=Custom"},
	}
}

// #10: explicit and PFX credentials must share key and exact Windows publisher.
func TestAuditSigningCredentials(t *testing.T) {
	for _, algorithm := range []string{"RSA", "ECDSA"} {
		t.Run(algorithm, func(t *testing.T) {
			var key, other crypto.Signer
			if algorithm == "RSA" {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				o, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				key, other = k, o
			} else {
				k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				o, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				key, other = k, o
			}
			cert := auditCert(t, key, nil)
			for _, tc := range []struct {
				name, publisher string
				key             crypto.Signer
				valid           bool
			}{{"valid", "CN=Test", key, true}, {"publisher mismatch", "CN=Other", key, false}, {"publisher case", "CN=test", key, false}, {"key mismatch", "CN=Test", other, false}} {
				t.Run(tc.name, func(t *testing.T) {
					b := auditBase().WithIdentity(auditIdentity().WithPublisher(tc.publisher).Build()).WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(tc.key).Build())
					data, err := auditBuild(b)
					if !tc.valid {
						require.Error(t, err)
						assert.Empty(t, data)
						return
					}
					require.NoError(t, err)
					sig := unzip(t, data)["AppxSignature.p7x"]
					p7, err := pkcs7.Parse(sig[4:])
					require.NoError(t, err)
					require.NoError(t, p7.Verify())
				})
			}
			pfx, err := pkcs12.Legacy.Encode(key, cert, nil, "audit")
			require.NoError(t, err)
			p := filepath.Join(t.TempDir(), "test.pfx")
			require.NoError(t, os.WriteFile(p, pfx, 0600))
			for _, publisher := range []string{"CN=Test", "CN=Other"} {
				data, err := auditBuild(auditBase().WithIdentity(auditIdentity().WithPublisher(publisher).Build()).WithSigning(msix.NewSigning().WithPFX(p, "audit").Build()))
				if publisher == "CN=Test" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					assert.Empty(t, data)
				}
			}
		})
	}
}
func TestAuditSigningPublisherFormatting(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, tc := range auditSubjects() {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := asn1.Marshal(tc.rdns)
			require.NoError(t, err)
			cert := auditCert(t, key, raw)
			_, err = auditBuild(auditBase().WithIdentity(auditIdentity().WithPublisher(tc.publisher).Build()).WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(key).Build()))
			require.NoError(t, err)
		})
	}
}
