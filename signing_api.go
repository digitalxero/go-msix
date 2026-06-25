package msix

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

// Signing is the runtime view of a code-signing configuration.
type Signing interface {
	isSigning()
}

// SigningBuilder configures code signing for an MSIX package.
type SigningBuilder interface {
	WithCertificate(*x509.Certificate) SigningBuilder
	WithPrivateKey(crypto.Signer) SigningBuilder
	WithCertChain(...*x509.Certificate) SigningBuilder
	// WithPFX loads the certificate, key and chain from a PFX/P12 file. The load is
	// deferred until Build so any error surfaces from Builder.Build.
	WithPFX(path, password string) SigningBuilder
	Build() Signing
}

// NewSigning returns a new SigningBuilder.
func NewSigning() SigningBuilder { return &signing{} }

// signingCreds is the resolved credential set used to produce the signature.
type signingCreds struct {
	cert  *x509.Certificate
	key   crypto.Signer
	chain []*x509.Certificate
}

type signing struct {
	cert    *x509.Certificate
	key     crypto.Signer
	chain   []*x509.Certificate
	pfxPath string
	pfxPass string
	usePFX  bool
}

func (s *signing) WithCertificate(c *x509.Certificate) SigningBuilder { s.cert = c; return s }
func (s *signing) WithPrivateKey(k crypto.Signer) SigningBuilder      { s.key = k; return s }
func (s *signing) WithCertChain(chain ...*x509.Certificate) SigningBuilder {
	s.chain = chain
	return s
}
func (s *signing) WithPFX(path, password string) SigningBuilder {
	s.pfxPath = path
	s.pfxPass = password
	s.usePFX = true
	return s
}
func (s *signing) Build() Signing { return s }
func (s *signing) isSigning()     {}

// resolve produces the concrete credentials, loading a PFX if configured.
func (s *signing) resolve() (*signingCreds, error) {
	if s.usePFX {
		cert, key, chain, err := LoadPFX(s.pfxPath, s.pfxPass)
		if err != nil {
			return nil, err
		}
		return &signingCreds{cert: cert, key: key, chain: chain}, nil
	}
	if s.cert == nil || s.key == nil {
		return nil, fmt.Errorf("msix: signing requires a certificate and private key")
	}
	return &signingCreds{cert: s.cert, key: s.key, chain: s.chain}, nil
}
