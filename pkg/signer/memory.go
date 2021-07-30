/*
Copyright The Rekor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/gcp"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const MemoryScheme = "memory"

// returns an in-memory signer and verify, used for spinning up local instances
type Memory struct {
	signature.ECDSASignerVerifier
}

// Generate a timestamping certificate for pub using the signer. The chain must verify the signer's public key if provided.
// Otherwise, a self-signed root CA will be generated.
func NewTimestampingCertWithChain(ctx context.Context, pub crypto.PublicKey, signer signature.Signer, chain []*x509.Certificate) ([]*x509.Certificate, error) {
	// Get the signer's (rekor's) public key
	signerPubKey, err := signer.PublicKey(options.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	// If the signer is not in-memory, retrieve the crypto.Signer
	var cryptoSigner crypto.Signer
	if s, ok := signer.(*gcp.SignerVerifier); ok {
		if cryptoSigner, _, err = s.CryptoSigner(ctx, func(err error) {}); err != nil {
			return nil, errors.Wrap(err, "getting kms signer")
		}
	} else {
		cryptoSigner = signer.(crypto.Signer)
	}

	if len(chain) == 0 {
		// Generate an in-memory self-signed root CA.
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(2019),
			Subject: pkix.Name{
				Organization: []string{"rekor in-memory root CA"},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			IsCA:                  true,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
		caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, signerPubKey, cryptoSigner)
		if err != nil {
			return nil, errors.Wrap(err, "creating self-signed CA")
		}
		chain, err = x509.ParseCertificates(caBytes)
		if err != nil {
			return nil, err
		}
	}

	timestampExt, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Rekor Timestamping Cert"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		KeyUsage:     x509.KeyUsageContentCommitment,
		IsCA:         false,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
				Critical: true,
				Value:    timestampExt,
			},
		},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, chain[0], pub, cryptoSigner)
	if err != nil {
		return nil, errors.Wrap(err, "creating tsa certificate")
	}
	tsaCert, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, err
	}

	// Verify and return the certificate chain
	root := x509.NewCertPool()
	root.AddCert(chain[len(chain)-1])
	intermediates := x509.NewCertPool()
	for _, intermediate := range chain[:len(chain)-1] {
		intermediates.AddCert(intermediate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         root,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err = tsaCert[0].Verify(verifyOptions); err != nil {
		return nil, err
	}
	return append(tsaCert, chain...), nil
}

func NewMemory() (*Memory, error) {
	// generate a keypair
	sv, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &Memory{
		ECDSASignerVerifier: *sv,
	}, nil
}
