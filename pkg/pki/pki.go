/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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

package pki

import (
	"fmt"
	"io"
	"strings"

	"github.com/projectrekor/rekor/pkg/pki/minisign"
	"github.com/projectrekor/rekor/pkg/pki/ssh"
	"github.com/projectrekor/rekor/pkg/pki/x509"

	"github.com/projectrekor/rekor/pkg/pki/pgp"
)

// PublicKey Generic object representing a public key (regardless of format & algorithm)
type PublicKey interface {
	CanonicalValue() ([]byte, error)
}

// Signature Generic object representing a signature (regardless of format & algorithm)
type Signature interface {
	CanonicalValue() ([]byte, error)
	Verify(r io.Reader, k interface{}) error
}

type ArtifactFactory struct {
	format string
}

func NewArtifactFactory(format string) *ArtifactFactory {
	return &ArtifactFactory{
		format: format,
	}
}

func (a ArtifactFactory) NewPublicKey(r io.Reader) (PublicKey, error) {
	switch strings.ToLower(a.format) {
	case "pgp":
		return pgp.NewPublicKey(r)
	case "minisign":
		return minisign.NewPublicKey(r)
	case "x509":
		return x509.NewPublicKey(r)
	case "ssh":
		return ssh.NewPublicKey(r)
	}
	return nil, fmt.Errorf("unknown key format '%v'", a.format)
}

func (a ArtifactFactory) NewSignature(r io.Reader) (Signature, error) {
	switch strings.ToLower(a.format) {
	case "pgp":
		return pgp.NewSignature(r)
	case "minisign":
		return minisign.NewSignature(r)
	case "x509":
		return x509.NewSignature(r)
	case "ssh":
		return ssh.NewSignature(r)
	}
	return nil, fmt.Errorf("unknown key format '%v'", a.format)
}
