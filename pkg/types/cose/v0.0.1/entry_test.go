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

package cose

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/spf13/viper"
	gocose "github.com/veraison/go-cose"
	"go.uber.org/goleak"
)

const (
	pubKeyP256 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5P3tzcNDA11znnCFF3DHLwiHNCl3
OXbUFakqff3cSRd4OTH1hiJgi15VIGSKZALlqjdWpf+fs87uRpiI6Yp59A==
-----END PUBLIC KEY-----
`
	pubKeyP384 = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPx88tPXP1ggkZHXnvg0vQAQ3vBlpKhF0
hVt3kEn4ug3o72Wa1JnJALuOALGn4tY5Xuv9jx4BG+DzbAcyMbC3ueuw6ppQcNEu
YJtZ/ty5vUBCekso165mLmAK+l5UXWTq
-----END PUBLIC KEY-----
`
	pubKeyP521 = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBRuRK30vNm09kt7AqbEtyZ4csZ943
5zgNvcYlqO9GOPA5rUu8lvjbwiELR4WPr9lzofDJY/I7gq8Hzdnl6snlyycBabpQ
Ndanm2XueC84SStD3ElF6JzjsD9QGljaVYWek6to/8luw5+1niH3hNDEw5jsqa2W
/r+0gL0QOCKvVsThqp4=
-----END PUBLIC KEY-----
`
	pubKeyRSA2048 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuqO4gwscYmCE3P8eM9eg
yIiElLNAzjWapPn99/uFAFKqkinGr/DAejP2zxgdXk+ESd8bO0Rqob1WZL8/HqQN
8kRkf2KfR7d6jFe06V7N/Fmh+3YCcNNS6K9eW86u31sjnszgdtmWDrXhsH+M0W8g
Q7rmo+7BUJAcU39iApN2GNsji6vrRLRiEnMP/fpnsLa8qYpPToSE0YVfWrKOvY2q
Qhg/LceADsJzdYP0Yp+Q2jdC1J5OvUC4Mq08YdD7EawWJ5JI2qEkcPgPn5SqPomS
ihKHDVzm+FqHEbgx0P57ZdKnk8kALNz5FFdwq46mbY8FRqGD56r4sB5rRcxy0cbB
EQIDAQAB
-----END PUBLIC KEY-----
`
	pubKeyEd25519 = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABhjHE6AOa33q2JGlVk9OjICRp2S6d9nUJh0Xr6PUego=
-----END PUBLIC KEY-----
`
)

type testPublicKey int

func (t testPublicKey) CanonicalValue() ([]byte, error) {
	return nil, nil
}

func (t testPublicKey) EmailAddresses() []string {
	return nil
}

func (t testPublicKey) Subjects() []string {
	return nil
}

func (t testPublicKey) Identities() ([]string, error) {
	return nil, nil
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestNewEntryReturnType(t *testing.T) {
	entry := NewEntry()
	if reflect.TypeOf(entry) != reflect.ValueOf(&V001Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func p(b []byte) *strfmt.Base64 {
	b64 := strfmt.Base64(b)
	return &b64
}

func makeSignedCose(t *testing.T, priv *ecdsa.PrivateKey, payload, aad []byte, contentType interface{}) []byte {
	m := gocose.NewSign1Message()
	m.Payload = payload
	m.Headers.Protected[gocose.HeaderLabelAlgorithm] = gocose.AlgorithmES256

	if contentType != "" {
		m.Headers.Protected[gocose.HeaderLabelContentType] = contentType
	}

	signer, err := gocose.NewSigner(gocose.AlgorithmES256, priv)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Sign(rand.Reader, aad, signer); err != nil {
		t.Fatal(err)
	}

	msg, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestV001Entry_Unmarshal(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	msg := makeSignedCose(t, priv, []byte("hello"), nil, "")
	msgWithAAD := makeSignedCose(t, priv, []byte("hello"), []byte("external aad"), "")

	tests := []struct {
		name            string
		want            models.CoseV001Schema
		it              *models.CoseV001Schema
		wantErr         bool
		wantVerifierErr bool
	}{
		{
			name:            "empty",
			it:              &models.CoseV001Schema{},
			wantErr:         true,
			wantVerifierErr: true,
		},
		{
			name: "missing data",
			it: &models.CoseV001Schema{
				PublicKey: p(pub),
			},
			wantErr:         true,
			wantVerifierErr: false,
		},
		{
			name: "missing envelope",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte("hello")),
			},
			wantErr:         true,
			wantVerifierErr: true,
		},
		{
			name: "valid",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr:         false,
			wantVerifierErr: false,
		},
		{
			name: "valid with aad",
			it: &models.CoseV001Schema{
				Data: &models.CoseV001SchemaData{
					Aad: strfmt.Base64("external aad"),
				},
				PublicKey: p(pub),
				Message:   msgWithAAD,
			},
			wantErr:         false,
			wantVerifierErr: false,
		},
		{
			name: "extra aad",
			it: &models.CoseV001Schema{
				Data: &models.CoseV001SchemaData{
					Aad: strfmt.Base64("aad"),
				},
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr:         true,
			wantVerifierErr: false,
		},
		{
			name: "invalid envelope",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte(pemBytes)),
				Message:   []byte("hello"),
			},
			wantErr:         true,
			wantVerifierErr: false,
		},
		{
			name: "cert",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte(pemBytes)),
				Message:   msg,
			},
			wantErr:         false,
			wantVerifierErr: false,
		},
		{
			name: "invalid key",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte("notavalidkey")),
				Message:   []byte("hello"),
			},
			wantErr:         true,
			wantVerifierErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V001Entry{
				CoseObj: models.CoseV001Schema{},
			}
			it := &models.Cose{
				Spec: tt.it,
			}
			if err := v.Unmarshal(it); (err != nil) != tt.wantErr {
				t.Errorf("V001Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if ok, err := v.Insertable(); !ok || err != nil {
					t.Errorf("unexpected error calling Insertable on valid proposed entry: %v", err)
				}
			}

			verifier, err := v.Verifier()
			if !tt.wantVerifierErr {
				if err != nil {
					s, _ := verifier.CanonicalValue()
					t.Errorf("%v: unexpected error for %v, got %v", tt.name, string(s), err)
				}

				if !tt.wantErr {
					b, err := v.Canonicalize(context.Background())
					if err != nil {
						t.Errorf("unexpected error canonicalizing %v", tt.name)
					}
					if len(b) != 0 {
						pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
						if err != nil {
							t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tt.name, err)
						}
						ei, err := types.UnmarshalEntry(pe)
						if err != nil {
							t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tt.name, err)
						}
						if ok, err := ei.Insertable(); ok || err == nil {
							t.Errorf("entry created from canonicalized entry should not also be insertable")
						}
					}
				}

				pubV, _ := verifier.CanonicalValue()
				if !reflect.DeepEqual(pubV, pub) && !reflect.DeepEqual(pubV, pemBytes) {
					t.Errorf("verifier and public keys do not match: %v, %v", string(pubV), string(pub))
				}
			} else if err == nil {
				s, _ := verifier.CanonicalValue()
				t.Errorf("%v: expected error for %v, got %v", tt.name, string(s), err)
			}
		})
	}

	t.Run("invalid type", func(t *testing.T) {
		want := "cannot unmarshal non Cose v0.0.1 type"
		v := V001Entry{}
		if err := v.Unmarshal(&types.BaseProposedEntryTester{}); err == nil {
			t.Error("expected error")
		} else if err.Error() != want {
			t.Errorf("wrong error: %s", err.Error())
		}
	})
}

func TestV001Entry_IndexKeys(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	attestation := `
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "foo",
      "digest": {
        "sha256": "ad92c12d7947cc04000948248ccf305682f395af3e109ed044081dbb40182e6c"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://example.com/test-builder"
    },
    "buildType": "test"
  }
}
`
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	rawMsg := []byte(attestation)
	msg := makeSignedCose(t, priv, rawMsg, nil, payloadType)
	pk, err := sigx509.NewPublicKey(bytes.NewReader(pub))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	v := V001Entry{
		CoseObj: models.CoseV001Schema{
			Message:   msg,
			Data:      &models.CoseV001SchemaData{},
			PublicKey: p(pub),
		},
		keyObj: pk,
	}
	err = v.validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Envelope digest
	sha := sha256.Sum256(msg)
	envDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, envDigest, got)

	// Message digest in envelope
	sha = sha256.Sum256(rawMsg)
	rawDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, rawDigest, got)

	// Subject from in-toto statement
	mustContain(t, "sha256:ad92c12d7947cc04000948248ccf305682f395af3e109ed044081dbb40182e6c", got)
}

func TestV001Entry_IndexKeysWrongContentType(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	rawMsg := []byte("this is not an intoto statement")
	msg := makeSignedCose(t, priv, rawMsg, nil, payloadType)
	pk, err := sigx509.NewPublicKey(bytes.NewReader(pub))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	v := V001Entry{
		CoseObj: models.CoseV001Schema{
			Message:   msg,
			Data:      &models.CoseV001SchemaData{},
			PublicKey: p(pub),
		},
		keyObj: pk,
	}
	err = v.validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Envelope digest
	sha := sha256.Sum256(msg)
	envDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, envDigest, got)

	// Message digest in envelope
	sha = sha256.Sum256(rawMsg)
	rawDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, rawDigest, got)
}

func TestV001Entry_IndexKeysIntegerContentType(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	rawMsg := []byte("hello")
	msg := makeSignedCose(t, priv, rawMsg, nil, 12345)
	pk, err := sigx509.NewPublicKey(bytes.NewReader(pub))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}

	v := V001Entry{
		CoseObj: models.CoseV001Schema{
			Message:   msg,
			Data:      &models.CoseV001SchemaData{},
			PublicKey: p(pub),
		},
		keyObj: pk,
	}
	err = v.validate()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
		return
	}
	got, err := v.IndexKeys()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Envelope digest
	sha := sha256.Sum256(msg)
	envDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, envDigest, got)

	// Message digest in envelope
	sha = sha256.Sum256(rawMsg)
	rawDigest := "sha256:" + hex.EncodeToString(sha[:])
	mustContain(t, rawDigest, got)
}

func TestV001Entry_Attestation(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Bytes: der,
		Type:  "PUBLIC KEY",
	})

	msg := makeSignedCose(t, priv, []byte("hello"), nil, "")

	it := &models.Cose{
		Spec: &models.CoseV001Schema{
			Data:      &models.CoseV001SchemaData{},
			PublicKey: p(pub),
			Message:   msg,
		},
	}

	t.Run("no storage", func(t *testing.T) {
		v := &V001Entry{
			CoseObj: models.CoseV001Schema{},
		}
		if err := v.Unmarshal(it); err != nil {
			t.Errorf("V001Entry.Unmarshal() error = %v", err)
		}
		key, att := v.AttestationKeyValue()
		if key != "" {
			t.Errorf("Unexpected key returned")
		}
		if len(att) != 0 {
			t.Errorf("Attestation returned")
		}
	})

	t.Run("with storage", func(t *testing.T) {
		// Need to trick viper to update config so we can return
		// an attestation
		os.Setenv("MAX_ATTESTATION_SIZE", "1048576")
		viper.AutomaticEnv()

		msgHash := sha256.Sum256(msg)
		wantKey := fmt.Sprintf("sha256:%s",
			hex.EncodeToString(msgHash[:]))

		v := &V001Entry{
			CoseObj: models.CoseV001Schema{},
		}
		if err := v.Unmarshal(it); err != nil {
			t.Errorf("V001Entry.Unmarshal() error = %v", err)
		}
		key, att := v.AttestationKeyValue()
		if key != wantKey {
			t.Errorf("unexpected attestation key: %s want: %s",
				key, wantKey)
		}

		if len(att) != len(msg) {
			t.Error("Wrong attestation returned")
		}
		for i := range att {
			if att[i] != msg[i] {
				t.Error("Wrong attestation returned")
				return
			}
		}
	})
}

func TestGetPublicKey(t *testing.T) {
	t.Run("P256", func(t *testing.T) {
		pk, err := sigx509.NewPublicKey(bytes.NewBufferString(pubKeyP256))
		if err != nil {
			t.Error("failed to load public key")
		}
		alg, cpk, err := getPublicKey(pk)
		if alg != gocose.AlgorithmES256 {
			t.Error("wrong algorithm")
		}
		if cpk == nil {
			t.Error("no public key returned")
		}
		if err != nil {
			t.Errorf("Unexpected error %s", err.Error())
		}
	})

	t.Run("P384", func(t *testing.T) {
		pk, err := sigx509.NewPublicKey(bytes.NewBufferString(pubKeyP384))
		if err != nil {
			t.Error("failed to load public key")
		}
		alg, cpk, err := getPublicKey(pk)
		if alg != gocose.Algorithm(0) {
			t.Error("unexpected algorithm returned")
		}
		if cpk != nil {
			t.Error("unexpected key returned")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("P521", func(t *testing.T) {
		pk, err := sigx509.NewPublicKey(bytes.NewBufferString(pubKeyP521))
		if err != nil {
			t.Error("failed to load public key")
		}
		alg, cpk, err := getPublicKey(pk)
		if alg != gocose.Algorithm(0) {
			t.Error("unexpected algorithm returned")
		}
		if cpk != nil {
			t.Error("unexpected key returned")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("RSA2048", func(t *testing.T) {
		pk, err := sigx509.NewPublicKey(bytes.NewBufferString(pubKeyRSA2048))
		if err != nil {
			t.Error("failed to load public key")
		}
		alg, cpk, err := getPublicKey(pk)
		if alg != gocose.AlgorithmPS256 {
			t.Error("unexpected algorithm returned")
		}
		if cpk == nil {
			t.Error("no public key returned")
		}
		if err != nil {
			t.Error("unexpected error")
		}
	})

	t.Run("Invalid key", func(t *testing.T) {
		alg, cpk, err := getPublicKey(testPublicKey(0))
		if alg != gocose.Algorithm(0) {
			t.Error("unexpected algorithm returned")
		}
		if cpk != nil {
			t.Error("unexpected key returned")
		}
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		pk, err := sigx509.NewPublicKey(bytes.NewBufferString(pubKeyEd25519))
		if err != nil {
			t.Error("failed to load public key")
		}
		alg, cpk, err := getPublicKey(pk)
		if alg != gocose.Algorithm(0) {
			t.Error("unexpected algorithm returned")
		}
		if cpk != nil {
			t.Error("unexpected key returned")
		}
		if err == nil {
			t.Error("expected error")
		}
		if err.Error() != "unsupported algorithm type ed25519.PublicKey" {
			t.Error("expected error")
		}
	})

}

func TestV001Entry_Validate(t *testing.T) {
	t.Run("missing message", func(t *testing.T) {
		v := V001Entry{}
		err := v.validate()
		if err != nil {
			t.Error("unexpected error")
		}
	})

	t.Run("invalid public key", func(t *testing.T) {
		v := V001Entry{}
		v.CoseObj.Message = []byte("string")
		v.keyObj, _ = sigx509.NewPublicKey(bytes.NewBufferString(pubKeyEd25519))
		err := v.validate()
		if err == nil {
			t.Error("expected error")
			return
		}
		if err.Error() != "unsupported algorithm type ed25519.PublicKey" {
			t.Error("wrong error returned")
		}
	})

}

func mustContain(t *testing.T, want string, l []string) {
	for _, s := range l {
		if s == want {
			return
		}
	}
	t.Fatalf("list %v does not contain %s", l, want)
}
