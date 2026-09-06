// Command gensignedmsix builds a self-signed-chain-signed sample MSIX for the
// external osslsigncode cross-check in scripts/verify_msix.sh and the
// windows-signature CI job. It writes to <out>:
//
//	signed.msix    the signed sample package
//	unsigned.msix  the same payload without signing (byte-equality baseline)
//	signer.pem     the ROOT certificate (PEM, for `osslsigncode verify -CAfile`)
//	root.cer       the ROOT certificate (DER, for Cert:\LocalMachine\Root)
//	leaf.cer       the leaf signing certificate (DER, for TrustedPeople)
//	signer.pfx     leaf key+cert+chain (password "go-msix", for signtool)
//
// The chain is root CA -> leaf so Windows chain policy sees a conformant
// end-entity code-signing certificate (a self-signed CA=true leaf is rejected
// with TRUST_E_BASIC_CONSTRAINTS). Keys are RSA — the algorithm Windows
// Authenticode reliably accepts for packages — and live only in memory.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/big"
	"os"
	"path/filepath"
	"time"

	msix "go.digitalxero.dev/go-msix"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// publisher must byte-match the leaf certificate subject or Windows refuses
// to sign/deploy the package.
const publisher = "CN=go-msix sample signer"

// PfxPassword protects signer.pfx; this is throwaway test material only.
const PfxPassword = "go-msix"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gensignedmsix <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	fail(os.MkdirAll(outDir, 0o755))

	now := time.Now()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fail(err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x90D51C01),
		Subject:               pkix.Name{CommonName: "go-msix sample root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	fail(err)
	rootCert, err := x509.ParseCertificate(rootDER)
	fail(err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	fail(err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x90D51C02),
		Subject:               pkix.Name{CommonName: "go-msix sample signer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, leafKey.Public(), rootKey)
	fail(err)
	leafCert, err := x509.ParseCertificate(leafDER)
	fail(err)

	logo := onePixelPNG()
	build := func() msix.Builder {
		return msix.NewBuilder().
			WithIdentity(msix.NewIdentity().WithName("GoMsix.SignedSample").
				WithVersion("1.0.0.0").WithPublisher(publisher).
				WithProcessorArchitecture("x64").Build()).
			WithProperties(msix.NewProperties().WithDisplayName("go-msix Signed Sample").
				WithPublisherDisplayName("go-msix").WithLogo("assets/logo.png").Build()).
			WithDependencies(msix.NewDependencies().
				AddTargetDeviceFamily("Windows.Desktop", "10.0.17763.0", "10.0.26100.0").Build()).
			WithCapabilities(msix.NewCapabilities().AddRestricted("runFullTrust").Build()).
			AddResource(msix.NewResource().WithLanguage("en-us").Build()).
			AddApplication(msix.NewApplication().WithID("App").
				WithExecutable("sample.exe").WithEntryPoint("Windows.FullTrustApplication").
				WithVisualElements(msix.NewVisualElements().WithDisplayName("go-msix Signed Sample").
					WithDescription("go-msix signed sample package").
					WithBackgroundColor("transparent").WithSquare150x150Logo("assets/logo.png").
					WithSquare44x44Logo("assets/logo.png").Build()).Build()).
			AddFileFromBytes("sample.exe", []byte("MZ go-msix signed sample payload")).
			AddFileFromBytes("assets/logo.png", logo)
	}

	var unsigned bytes.Buffer
	fail(build().Build(context.Background(), &unsigned))
	fail(os.WriteFile(filepath.Join(outDir, "unsigned.msix"), unsigned.Bytes(), 0o644))

	var signed bytes.Buffer
	fail(build().
		WithSigning(msix.NewSigning().
			WithCertificate(leafCert).WithPrivateKey(leafKey).
			WithCertChain(rootCert).Build()).
		Build(context.Background(), &signed))
	fail(os.WriteFile(filepath.Join(outDir, "signed.msix"), signed.Bytes(), 0o644))

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	fail(os.WriteFile(filepath.Join(outDir, "signer.pem"), rootPEM, 0o644))
	fail(os.WriteFile(filepath.Join(outDir, "root.cer"), rootDER, 0o644))
	fail(os.WriteFile(filepath.Join(outDir, "leaf.cer"), leafDER, 0o644))

	pfx, err := gopkcs12.Legacy.Encode(leafKey, leafCert, []*x509.Certificate{rootCert}, PfxPassword)
	fail(err)
	fail(os.WriteFile(filepath.Join(outDir, "signer.pfx"), pfx, 0o644))

	fmt.Println("wrote signed.msix, unsigned.msix, signer.pem, root.cer, leaf.cer, signer.pfx")
}

func onePixelPNG() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	img.SetNRGBA(0, 0, color.NRGBA{R: 0x33, G: 0x99, B: 0xff, A: 0xff})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "gensignedmsix:", err)
		os.Exit(1)
	}
}
