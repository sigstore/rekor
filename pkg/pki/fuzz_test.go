//
// Copyright 2022 The Sigstore Authors.
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

package pki

import (
	"bytes"
	"io"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/minisign"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/pki/pkcs7"
	"github.com/sigstore/rekor/pkg/pki/ssh"
	"github.com/sigstore/rekor/pkg/pki/tuf"
	"github.com/sigstore/rekor/pkg/pki/x509"
)

var (
	fuzzArtifactFactoryMap = map[uint]pkiImpl{
		0: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return pgp.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return pgp.NewSignature(r)
			},
		},
		1: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return minisign.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return minisign.NewSignature(r)
			},
		},
		2: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return ssh.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return ssh.NewSignature(r)
			},
		},
		3: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return x509.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return x509.NewSignature(r)
			},
		},
		4: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return pkcs7.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return pkcs7.NewSignature(r)
			},
		},
		5: {
			newPubKey: func(r io.Reader) (PublicKey, error) {
				return tuf.NewPublicKey(r)
			},
			newSignature: func(r io.Reader) (Signature, error) {
				return tuf.NewSignature(r)
			},
		},
	}
)

func FuzzKeys(f *testing.F) {
	f.Fuzz(func(t *testing.T, keyType uint, origSignatureData, verSignatureData, keyData []byte) {
		s, err := fuzzArtifactFactoryMap[keyType%6].newSignature(bytes.NewReader(origSignatureData))
		if err == nil && s != nil {
			b, err := s.CanonicalValue()
			if err == nil {
				_, err = fuzzArtifactFactoryMap[keyType%6].newSignature(bytes.NewReader(b))
				if err != nil {
					t.Fatal("Could not create a signature from valid key data")
				}
			}
			pub, err := fuzzArtifactFactoryMap[keyType%6].newPubKey(bytes.NewReader(keyData))
			if err != nil {
				t.Skip()
			}
			s.Verify(bytes.NewReader(verSignatureData), pub)
		}
	})
}
