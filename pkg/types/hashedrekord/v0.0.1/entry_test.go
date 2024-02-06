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

package hashedrekord

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	x509r "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V001Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func TestRejectsSHA1(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key: %v", err)
	}
	pubBytes, err := cryptoutils.MarshalPublicKeyToPEM(privKey.Public())
	if err != nil {
		t.Fatalf("error marshaling public key: %v", err)
	}

	data := []byte("data")
	signer, err := signature.LoadSigner(privKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("error loading verifier: %v", err)
	}
	signature, err := signer.SignMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("error signing message: %v", err)
	}

	ap := types.ArtifactProperties{
		ArtifactBytes:  data,
		ArtifactHash:   "sha1:a17c9aaa61e80a1bf71d0d850af4e5baa9800bbd",
		PublicKeyBytes: [][]byte{pubBytes},
		PKIFormat:      "x509",
		SignatureBytes: signature,
	}

	ei := NewEntry()
	_, err = ei.CreateFromArtifactProperties(context.Background(), ap)
	if err == nil {
		t.Fatalf("expected error creating entry")
	}
}

func TestCrossFieldValidation(t *testing.T) {
	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectedHashValue         string
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
		expectedVerifierSuccess   bool
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	// testing support ed25519
	edPubKey, edPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDer, err := x509.MarshalPKIXPublicKey(edPubKey)
	if err != nil {
		t.Fatal(err)
	}
	edPubKeyBytes := pem.EncodeToMemory(&pem.Block{
		Bytes: edDer,
		Type:  "PUBLIC KEY",
	})

	dataBytes := []byte("sign me!")
	sha256Sum := sha256.Sum256(dataBytes)
	sha384Sum := sha512.Sum384(dataBytes)
	sha512Sum := sha512.Sum512(dataBytes)
	dataSHA256 := hex.EncodeToString(sha256Sum[:])
	dataSHA384 := hex.EncodeToString(sha384Sum[:])
	dataSHA512 := hex.EncodeToString(sha512Sum[:])

	sha256Signer, _ := signature.LoadSigner(key, crypto.SHA256)
	sha256SigBytes, _ := sha256Signer.SignMessage(bytes.NewReader(dataBytes))
	sha384Signer, _ := signature.LoadSigner(key, crypto.SHA384)
	sha384SigBytes, _ := sha384Signer.SignMessage(bytes.NewReader(dataBytes))
	sha512Signer, _ := signature.LoadSigner(key, crypto.SHA512)
	sha512SigBytes, _ := sha512Signer.SignMessage(bytes.NewReader(dataBytes))

	edsha512Signer, _ := signature.LoadSignerWithOpts(edPrivKey, options.WithHash(crypto.SHA512), options.WithED25519ph())
	edsha512SigBytes, _ := edsha512Signer.SignMessage(bytes.NewReader(dataBytes))

	incorrectLengthHash := sha256.Sum224(dataBytes)
	incorrectLengthSHA := hex.EncodeToString(incorrectLengthHash[:])

	badHash := sha256.Sum256(keyBytes)
	badDataSHA := hex.EncodeToString(badHash[:])

	testCases := []TestCase{
		{
			caseDesc:                "empty obj",
			entry:                   V001Entry{},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature without url or content",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{},
				},
			},
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature without public key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
					},
				},
			},
			expectedHashValue:       "sha256:" + dataSHA256,
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature with empty public key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content:   sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{},
					},
				},
			},
			expectedHashValue:       "sha256:" + dataSHA256,
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: false,
		},
		{
			caseDesc: "signature with ed25519 public key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: edsha512SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: edPubKeyBytes,
						},
					},
				},
			},
			expectedHashValue:       "sha512:" + dataSHA512,
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "signature without data",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
				},
			},
			expectedHashValue:       "sha256:" + dataSHA256,
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "signature with empty data",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{},
				},
			},
			expectedHashValue:       "sha256:" + dataSHA256,
			expectUnmarshalSuccess:  false,
			expectedVerifierSuccess: true,
		},
		{
			caseDesc: "signature with ed25519 public key (with data)",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: edsha512SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: edPubKeyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha512),
							Value:     swag.String(dataSHA512),
						},
					},
				},
			},
			expectedHashValue:         "sha512:" + dataSHA512,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with sha256 hash",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(dataSHA256),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
				},
			},
			expectedHashValue:         "sha256:" + dataSHA256,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with sha384 hash",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha384SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(dataSHA384),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha384),
						},
					},
				},
			},
			expectedHashValue:         "sha384:" + dataSHA384,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with sha512 hash",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha512SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(dataSHA512),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha512),
						},
					},
				},
			},
			expectedHashValue:         "sha512:" + dataSHA512,
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with invalid sha length",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(incorrectLengthSHA),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
				},
			},
			expectedHashValue:         "sha256:" + dataSHA256,
			expectUnmarshalSuccess:    false,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with hash & invalid signature",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha256SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(badDataSHA),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
				},
			},
			expectedHashValue:         "sha256:" + dataSHA256,
			expectUnmarshalSuccess:    false,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
		{
			caseDesc: "signature with mismatched hash & invalid signature",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sha512SigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(dataSHA256),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
				},
			},
			expectedHashValue:         "sha256:" + dataSHA256,
			expectUnmarshalSuccess:    false,
			expectCanonicalizeSuccess: false,
			expectedVerifierSuccess:   true,
		},
	}

	for _, tc := range testCases {
		if _, _, err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		v := &V001Entry{}
		r := models.Hashedrekord{
			APIVersion: swag.String(tc.entry.APIVersion()),
			Spec:       tc.entry.HashedRekordObj,
		}

		unmarshalAndValidate := func() error {
			if err := v.Unmarshal(&r); err != nil {
				return err
			}
			if _, _, err := v.validate(); err != nil {
				return err
			}
			return nil
		}

		if err := unmarshalAndValidate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
		}

		if tc.expectUnmarshalSuccess {
			ok, err := v.Insertable()
			if !ok || err != nil {
				t.Errorf("unexpected failure in testing insertable on valid entry: %v", err)
			}

			hash, err := v.ArtifactHash()
			if err != nil {
				t.Errorf("unexpected failure with ArtifactHash: %v", err)
			} else if hash != tc.expectedHashValue {
				t.Errorf("unexpected match with ArtifactHash: %s", hash)
			}
		}

		b, err := v.Canonicalize(context.TODO())
		if (err == nil) != tc.expectCanonicalizeSuccess {
			t.Errorf("unexpected result from Canonicalize for '%v': %v", tc.caseDesc, err)
		} else if err != nil {
			if _, ok := err.(types.ValidationError); !ok {
				t.Errorf("canonicalize returned an unexpected error that isn't of type types.ValidationError: %v", err)
			}
		}
		if b != nil {
			pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
			if err != nil {
				t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tc.caseDesc, err)
			}
			ei, err := types.UnmarshalEntry(pe)
			if err != nil {
				t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tc.caseDesc, err)
			}
			// hashedrekord is one of two types (rfc3161, hashedrekord) in that what is persisted is also insertable
			ok, err := ei.Insertable()
			if !ok || err != nil {
				t.Errorf("unexpected failure in testing insertable on entry created from canonicalized content: %v", err)
			}
			hash, err := ei.ArtifactHash()
			if err != nil {
				t.Errorf("unexpected failure with ArtifactHash: %v", err)
			} else if hash != tc.expectedHashValue {
				t.Errorf("unexpected match with ArtifactHash: %s", hash)
			}
		}

		verifiers, err := v.Verifiers()
		if tc.expectedVerifierSuccess {
			if err != nil {
				t.Errorf("%v: unexpected error, got %v", tc.caseDesc, err)
			} else {
				pub, _ := verifiers[0].CanonicalValue()
				if !reflect.DeepEqual(pub, keyBytes) && !reflect.DeepEqual(pub, edPubKeyBytes) {
					t.Errorf("verifier and public keys do not match: %v, %v", string(pub), string(keyBytes))
				}
			}
		} else {
			if err == nil {
				s, _ := verifiers[0].CanonicalValue()
				t.Errorf("%v: expected error for %v, got %v", tc.caseDesc, string(s), err)
			}
		}
	}
}

func hexHash(b []byte) string {
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:])
}

func TestV001Entry_IndexKeys(t *testing.T) {
	pub, cert, priv := testKeyAndCert(t)

	data := "my random data"
	h := sha256.Sum256([]byte(data))
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatal(err)
	}

	hashStr := hex.EncodeToString(h[:])
	hashIndexKey := "sha256:" + hashStr
	// Base entry template
	v := V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: swag.String("sha256"),
					Value:     swag.String(hashStr),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content:   strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{},
			},
		},
	}

	// Test with a public key and a cert

	// For the public key, we should have the key and the hash.
	t.Run("public key", func(t *testing.T) {
		v.HashedRekordObj.Signature.PublicKey.Content = strfmt.Base64(pub)

		k, err := v.IndexKeys()
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]struct{}{}
		for _, key := range k {
			keys[key] = struct{}{}
		}

		if _, ok := keys[hashIndexKey]; !ok {
			t.Errorf("missing hash index entry %s, got %v", hashIndexKey, keys)
		}
		want := hexHash(pub)
		if _, ok := keys[want]; !ok {
			t.Errorf("missing key index entry %s, got %v", want, keys)
		}
	})

	// For the public key, we should have the key and the hash.
	t.Run("cert", func(t *testing.T) {
		v.HashedRekordObj.Signature.PublicKey.Content = strfmt.Base64(cert)

		k, err := v.IndexKeys()
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string]struct{}{}
		for _, key := range k {
			keys[key] = struct{}{}
		}

		if _, ok := keys[hashIndexKey]; !ok {
			t.Errorf("missing hash index entry for public key test, got %v", keys)
		}
		if _, ok := keys[hexHash(cert)]; !ok {
			t.Errorf("missing key index entry for public key test, got %v", keys)
		}
	})

}

func testKeyAndCert(t *testing.T) ([]byte, []byte, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Names: []pkix.AttributeTypeAndValue{
				{
					Type:  x509r.EmailAddressOID,
					Value: "foo@bar.com",
				},
			},
		},
	}
	cb, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cb,
	})

	return pub, certPem, priv
}

func TestInsertable(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         V001Entry
		expectSuccess bool
	}

	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing key content",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content:   strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing key content",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content:   strfmt.Base64("sig"),
						PublicKey: nil,
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing sig content",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: nil,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing hash value",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing hash algorithm",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value: swag.String("deadbeef"),
						},
					},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing hash object",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{},
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing data object",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: strfmt.Base64("sig"),
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: strfmt.Base64("key"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing sig object",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
							Value:     swag.String("deadbeef"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "empty object",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{},
			},
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.caseDesc, func(t *testing.T) {
			if ok, err := tc.entry.Insertable(); ok != tc.expectSuccess {
				t.Errorf("unexpected result calling Insertable: %v", err)
			}
		})
	}
}
