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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag"
	"go.uber.org/goleak"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
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

func TestCrossFieldValidation(t *testing.T) {
	type TestCase struct {
		caseDesc                  string
		entry                     V001Entry
		expectUnmarshalSuccess    bool
		expectCanonicalizeSuccess bool
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

	dataBytes := []byte("sign me!")
	h := sha256.Sum256(dataBytes)
	dataSHA := hex.EncodeToString(h[:])

	signer, _ := signature.LoadSigner(key, crypto.SHA256)
	sigBytes, _ := signer.SignMessage(bytes.NewReader(dataBytes))

	incorrectLengthHash := sha256.Sum224(dataBytes)
	incorrectLengthSHA := hex.EncodeToString(incorrectLengthHash[:])

	badHash := sha256.Sum256(keyBytes)
	badDataSHA := hex.EncodeToString(badHash[:])

	testCases := []TestCase{
		{
			caseDesc:               "empty obj",
			entry:                  V001Entry{},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without url or content",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without public key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty public key",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content:   sigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{},
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature without data",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with empty data",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{},
				},
			},
			expectUnmarshalSuccess: false,
		},
		{
			caseDesc: "signature with hash",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
						PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
							Content: keyBytes,
						},
					},
					Data: &models.HashedrekordV001SchemaData{
						Hash: &models.HashedrekordV001SchemaDataHash{
							Value:     swag.String(dataSHA),
							Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
						},
					},
				},
			},
			expectUnmarshalSuccess:    true,
			expectCanonicalizeSuccess: true,
		},
		{
			caseDesc: "signature with invalid sha length",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
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
			expectUnmarshalSuccess:    false,
			expectCanonicalizeSuccess: false,
		},
		{
			caseDesc: "signature with hash & invalid signature",
			entry: V001Entry{
				HashedRekordObj: models.HashedrekordV001Schema{
					Signature: &models.HashedrekordV001SchemaSignature{
						Content: sigBytes,
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
			expectUnmarshalSuccess:    false,
			expectCanonicalizeSuccess: false,
		},
	}

	for _, tc := range testCases {
		if err := tc.entry.validate(); (err == nil) != tc.expectUnmarshalSuccess {
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
			if err := v.validate(); err != nil {
				return err
			}
			return nil
		}

		if err := unmarshalAndValidate(); (err == nil) != tc.expectUnmarshalSuccess {
			t.Errorf("unexpected result in '%v': %v", tc.caseDesc, err)
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
			if _, err := types.NewEntry(pe); err != nil {
				t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tc.caseDesc, err)
			}
		}
	}
}
