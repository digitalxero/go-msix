// Command gensignedmsix builds a self-signed-certificate-signed sample MSIX for
// the external osslsigncode cross-check in scripts/verify_msix.sh and the
// windows-signature CI job. It writes to <out>:
//
//	signed.msix    the signed sample package
//	unsigned.msix  the same payload without signing (byte-equality baseline)
//	signer.pem     the signing certificate (PEM, for `osslsigncode verify -CAfile`)
//	signer.cer     the signing certificate (DER, for Windows Import-Certificate)
//
// The key is RSA (the only algorithm Windows Authenticode reliably accepts for
// packages), lives only in memory, and the certificate is valid for one day.
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
)

// publisher must byte-match the certificate subject or Windows refuses to
// deploy the package (0x800B0100-family errors from Add-AppxPackage).
const publisher = "CN=go-msix sample signer"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gensignedmsix <output-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	fail(os.MkdirAll(outDir, 0o755))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	fail(err)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(0x90D51C),
		Subject:               pkix.Name{CommonName: "go-msix sample signer"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:                  true, // self-signed; usable as its own trust anchor
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	fail(err)
	cert, err := x509.ParseCertificate(certDER)
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
		WithSigning(msix.NewSigning().WithCertificate(cert).WithPrivateKey(key).Build()).
		Build(context.Background(), &signed))
	fail(os.WriteFile(filepath.Join(outDir, "signed.msix"), signed.Bytes(), 0o644))

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fail(os.WriteFile(filepath.Join(outDir, "signer.pem"), pemBytes, 0o644))
	fail(os.WriteFile(filepath.Join(outDir, "signer.cer"), certDER, 0o644))

	fmt.Println("wrote signed.msix, unsigned.msix, signer.pem, signer.cer")
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
