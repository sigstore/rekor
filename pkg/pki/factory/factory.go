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

package factory

import (
	"fmt"
	"io"

	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/minisign"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/pki/pkcs7"
	"github.com/sigstore/rekor/pkg/pki/ssh"
	"github.com/sigstore/rekor/pkg/pki/x509"
)

type PKIFormat string

const (
	PGP      PKIFormat = "pgp"
	Minisign PKIFormat = "minisign"
	SSH      PKIFormat = "ssh"
	X509     PKIFormat = "x509"
	PKCS7    PKIFormat = "pkcs7"
)

type ArtifactFactory struct {
	impl pkiImpl
}

func NewArtifactFactory(format string) (*ArtifactFactory, error) {
	if impl, ok := artifactFactoryMap[PKIFormat(format)]; ok {
		return &ArtifactFactory{impl: impl}, nil
	}
	return nil, fmt.Errorf("%v is not a supported PKI format", format)
}

type pkiImpl struct {
	newPubKey    func(io.Reader) (pki.PublicKey, error)
	newSignature func(io.Reader) (pki.Signature, error)
}

var artifactFactoryMap map[PKIFormat]pkiImpl

func init() {
	artifactFactoryMap = map[PKIFormat]pkiImpl{
		PGP: {
			newPubKey:    pgp.NewPublicKey,
			newSignature: pgp.NewSignature,
		},
		Minisign: {
			newPubKey:    minisign.NewPublicKey,
			newSignature: minisign.NewSignature,
		},
		SSH: {
			newPubKey:    ssh.NewPublicKey,
			newSignature: ssh.NewSignature,
		},
		X509: {
			newPubKey:    x509.NewPublicKey,
			newSignature: x509.NewSignature,
		},
		PKCS7: {
			newPubKey:    pkcs7.NewPublicKey,
			newSignature: pkcs7.NewSignature,
		},
	}
}

func SupportedFormats() []string {
	var formats []string
	for f := range artifactFactoryMap {
		formats = append(formats, string(f))
	}
	return formats
}

func (a ArtifactFactory) NewPublicKey(r io.Reader) (pki.PublicKey, error) {
	return a.impl.newPubKey(r)
}

func (a ArtifactFactory) NewSignature(r io.Reader) (pki.Signature, error) {
	return a.impl.newSignature(r)
}
