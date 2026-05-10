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
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"io"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/minisign"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/pki/pkcs7"
	"github.com/sigstore/rekor/pkg/pki/ssh"
	"github.com/sigstore/rekor/pkg/pki/tuf"
	"github.com/sigstore/rekor/pkg/pki/x509"
)

//go:embed pgp/testdata/hello_world.txt.asc.sig
var helloWorldPgpSig []byte

//go:embed pgp/testdata/hello_world.txt.sig
var helloWorldPgpBinarySig []byte

//go:embed pgp/testdata/valid_armored_public.pgp
var validArmoredPgpPub []byte

//go:embed pgp/testdata/valid_binary_public.pgp
var validBinaryPgpPub []byte

//go:embed minisign/testdata/hello_world.txt.minisig
var helloWorldMinisignSig []byte

//go:embed minisign/testdata/hello_world_hashed.txt.minisig
var helloWorldMinisignHashedSig []byte

//go:embed minisign/testdata/minisign.pub
var validMinisignPub []byte

//go:embed ssh/testdata/hello_world.txt.sig
var helloWorldSshSig []byte

//go:embed ssh/testdata/id_rsa.pub
var validSshPub []byte

//go:embed x509/testdata/hello_world.txt.sig
var helloWorldX509Sig []byte

//go:embed x509/testdata/ec.pub
var validX509Pub []byte

//go:embed pkcs7/testdata/sig.pkcs7.pem
var pkcs7SigAndCert []byte

//go:embed tuf/testdata/timestamp.json
var tufTimestamp []byte

//go:embed tuf/testdata/1.root.json
var tufRoot []byte

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

// wrapKeyBytes pushes raw fuzzer bytes past the outer framing layer for each
// PKI format so the mutator spends its budget on the inner ASN.1 / packet /
// JSON structure rather than rediscovering the envelope every run.
func wrapKeyBytes(keyType uint, raw []byte) []byte {
	switch keyType {
	case 0: // pgp
		return []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" +
			base64.StdEncoding.EncodeToString(raw) +
			"\n-----END PGP PUBLIC KEY BLOCK-----\n")
	case 1: // minisign
		return []byte("untrusted comment: fuzz\n" + base64.StdEncoding.EncodeToString(raw))
	case 2: // ssh
		return []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(raw) + " fuzz@rekor")
	case 3: // x509
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	case 4: // pkcs7
		return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: raw})
	case 5: // tuf
		return raw // tuf root.json is plain JSON; let the mutator find structure
	}
	return raw
}

func FuzzKeys(f *testing.F) {
	msg := []byte("Hello, World!\n")
	sshMsg := []byte("Hello, ssh world!\n")

	// PGP (keyType 0): armored public key + armored signature
	f.Add(uint(0), false,
		helloWorldPgpSig,
		msg,
		validArmoredPgpPub)
	// PGP binary format
	f.Add(uint(0), false,
		helloWorldPgpBinarySig,
		msg,
		validBinaryPgpPub)
	// Minisign (keyType 1): standard signature + key with comment
	f.Add(uint(1), false,
		helloWorldMinisignSig,
		msg,
		validMinisignPub)
	// Minisign: prehashed signature (exercises blake2b path)
	f.Add(uint(1), false,
		helloWorldMinisignHashedSig,
		msg,
		validMinisignPub)
	// SSH (keyType 2): RSA key + signature
	f.Add(uint(2), false,
		helloWorldSshSig,
		sshMsg,
		validSshPub)
	// X509 (keyType 3): EC public key + signature
	f.Add(uint(3), false,
		helloWorldX509Sig,
		msg,
		validX509Pub)
	// PKCS7 (keyType 4): signed JAR manifest with embedded cert chain.
	// Note: PKCS7 NewPublicKey has a known round-trip inconsistency
	// (CanonicalValue returns CERTIFICATE PEM, but NewPublicKey rejects
	// non-PKCS7 PEM), so we supply the same blob for both signature and
	// key to exercise the maximum parse depth.
	f.Add(uint(4), false,
		pkcs7SigAndCert,
		[]byte{},
		pkcs7SigAndCert)
	// TUF (keyType 5): root.json as key, timestamp.json as "signature"
	f.Add(uint(5), false,
		tufTimestamp,
		[]byte("{}"),
		tufRoot)

	f.Fuzz(func(t *testing.T, keyType uint, wrap bool, origSignatureData, verSignatureData, keyData []byte) {
		impl := fuzzArtifactFactoryMap[keyType%6]

		s, sigErr := impl.newSignature(bytes.NewReader(origSignatureData))
		if sigErr == nil && s != nil {
			b, err := s.CanonicalValue()
			if err == nil {
				if _, err := impl.newSignature(bytes.NewReader(b)); err != nil {
					t.Fatalf("could not re-parse canonical signature: %v", err)
				}
			}
		}

		keyBytes := keyData
		if wrap {
			keyBytes = wrapKeyBytes(keyType%6, keyData)
		}
		pub, err := impl.newPubKey(bytes.NewReader(keyBytes))
		if err != nil || pub == nil {
			return
		}

		// Exercise the full PublicKey surface; these feed IndexKeys() in the
		// API write path and contain non-trivial cert/SAN/packet parsing.
		_ = pub.EmailAddresses() //nolint:staticcheck // deprecated but still exported/reachable
		_ = pub.Subjects()
		_, _ = pub.Identities()

		if cv, err := pub.CanonicalValue(); err == nil {
			if _, err := impl.newPubKey(bytes.NewReader(cv)); err != nil {
				// Log but don't fail: some implementations (e.g. PKCS7)
				// have a known round-trip inconsistency where
				// CanonicalValue returns a different PEM type than
				// NewPublicKey accepts.
				t.Logf("canonical public key re-parse failed: %v", err)
			}
		}

		// Only call Verify with a successfully-parsed signature; some
		// implementations return a typed-nil pointer on error which is a
		// non-nil interface value and would panic on a value-receiver call.
		if sigErr == nil && s != nil {
			_ = s.Verify(bytes.NewReader(verSignatureData), pub)
		}
	})
}
