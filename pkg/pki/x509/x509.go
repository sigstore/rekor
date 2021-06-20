//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package x509

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/go-playground/validator"
)

// EmailAddressOID defined by https://oidref.com/1.2.840.113549.1.9.1
var EmailAddressOID asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 9, 1}

type Signature struct {
	signature []byte
}

// NewSignature creates and validates an x509 signature object
func NewSignature(r io.Reader) (*Signature, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return &Signature{
		signature: b,
	}, nil
}

// CanonicalValue implements the pki.Signature interface
func (s Signature) CanonicalValue() ([]byte, error) {
	return s.signature, nil
}

// Verify implements the pki.Signature interface
func (s Signature) Verify(r io.Reader, k interface{}) error {
	if len(s.signature) == 0 {
		//lint:ignore ST1005 X509 is proper use of term
		return fmt.Errorf("X509 signature has not been initialized")
	}

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)
	message, err := ioutil.ReadAll(tee)
	if err != nil {
		return err
	}
	hash := hasher.Sum(nil)

	key, ok := k.(*PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key type for: %v", k)
	}

	p := key.key
	if p == nil {
		p = key.cert.c.PublicKey
	}

	switch pub := p.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash, s.signature)
	case ed25519.PublicKey:
		if ed25519.Verify(pub, message, s.signature) {
			return nil
		}
		return errors.New("supplied signature does not match key")
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, hash, s.signature) {
			return nil
		}
		return errors.New("supplied signature does not match key")
	default:
		return fmt.Errorf("invalid public key type: %T", pub)
	}
}

// PublicKey Public Key that follows the x509 standard
type PublicKey struct {
	key  interface{}
	cert *cert
}

type cert struct {
	c *x509.Certificate
	b []byte
}

// NewPublicKey implements the pki.PublicKey interface
func NewPublicKey(r io.Reader) (*PublicKey, error) {
	rawPub, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawPub)
	if block == nil {
		return nil, fmt.Errorf("invalid public key: %s", string(rawPub))
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &PublicKey{key: key}, nil
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &PublicKey{
			cert: &cert{
				c: c,
				b: block.Bytes,
			}}, nil
	}
	return nil, fmt.Errorf("invalid public key: %s", string(rawPub))
}

// CanonicalValue implements the pki.PublicKey interface
func (k PublicKey) CanonicalValue() ([]byte, error) {

	var p pem.Block
	switch {
	case k.key != nil:
		b, err := x509.MarshalPKIXPublicKey(k.key)
		if err != nil {
			return nil, err
		}

		p = pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}
	case k.cert != nil:
		p = pem.Block{
			Type:  "CERTIFICATE",
			Bytes: k.cert.b,
		}
	default:
		return nil, fmt.Errorf("x509 public key has not been initialized")
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (k PublicKey) CryptoPubKey() crypto.PublicKey {
	return k.key
}

// EmailAddresses implements the pki.PublicKey interface
func (k PublicKey) EmailAddresses() []string {
	var names []string
	if k.cert != nil {
		for _, name := range k.cert.c.EmailAddresses {
			validate := validator.New()
			errs := validate.Var(name, "required,email")
			if errs == nil {
				names = append(names, strings.ToLower(name))
			}
		}
	}
	return names
}

func CertChainToPEM(certChain []*x509.Certificate) ([]byte, error) {
	var pemBytes bytes.Buffer
	for _, cert := range certChain {
		if err := pem.Encode(&pemBytes, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, err
		}
	}
	return pemBytes.Bytes(), nil
}

func ParseTimestampCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	certChain := []*x509.Certificate{}
	var block *pem.Block
	block, pemBytes = pem.Decode(pemBytes)
	for ; block != nil; block, pemBytes = pem.Decode(pemBytes) {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certChain = append(certChain, cert)
		} else {
			return nil, errors.New("invalid block type")
		}
	}
	if len(certChain) == 0 {
		return nil, errors.New("no valid certificates in chain")
	}
	// Verify cert chain for timestamping
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, cert := range certChain[1:(len(certChain) - 1)] {
		intermediates.AddCert(cert)
	}
	roots.AddCert(certChain[len(certChain)-1])
	if _, err := certChain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		Intermediates: intermediates,
	}); err != nil {
		return nil, err
	}
	return certChain, nil
}
