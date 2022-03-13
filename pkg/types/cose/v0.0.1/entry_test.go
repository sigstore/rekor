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

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	gocose "github.com/veraison/go-cose"
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

func p(b []byte) *strfmt.Base64 {
	b64 := strfmt.Base64(b)
	return &b64
}

func makeSignedCose(t *testing.T, priv crypto.PrivateKey, payload []byte) []byte {
	m := gocose.NewSign1Message()
	m.Headers.Protected[1] = -7

	signer, err := gocose.NewSignerFromKey(gocose.ES256, priv)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Sign(rand.Reader, payload, *signer); err != nil {
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

	msg := makeSignedCose(t, priv, []byte("hello"))

	tests := []struct {
		name    string
		want    models.CoseV001Schema
		it      *models.CoseV001Schema
		wantErr bool
	}{
		{
			name:    "empty",
			it:      &models.CoseV001Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.CoseV001Schema{
				PublicKey: p(pub),
			},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.CoseV001Schema{
				PublicKey: p([]byte("hello")),
			},
			wantErr: true,
		},
		{
			name: "valid",
			it: &models.CoseV001Schema{
				PublicKey: p(pub),
				Data: &models.CoseV001SchemaData{
					Content: p([]byte("hello")),
				},
			},
			wantErr: false,
		},
		{
			name: "cert",
			it: &models.CoseV001Schema{
				PublicKey: p([]byte(pemBytes)),
				Data: &models.CoseV001SchemaData{
					Content: p([]byte("hello")),
				},
			},
			wantErr: false,
		},
		{
			name: "invalid key",
			it: &models.CoseV001Schema{
				PublicKey: p([]byte("notavalidkey")),
				Data: &models.CoseV001SchemaData{
					Content: p([]byte("hello")),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V001Entry{
				CoseObj: models.CoseV001Schema{
					Message: (*strfmt.Base64)(&msg),
					Data: &models.CoseV001SchemaData{
						Content: p([]byte("hello")),
					},
				},
			}
			tt.it.Message = (*strfmt.Base64)(&msg)
			it := &models.Cose{
				Spec: tt.it,
			}
			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}
				if err := v.validate(); err != nil {
					return err
				}
				return nil
			}
			if err := uv(); (err != nil) != tt.wantErr {
				t.Errorf("V001Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestV001Entry_IndexKeys(t *testing.T) {

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
	msg := makeSignedCose(t, priv, rawMsg)

	v := V001Entry{
		CoseObj: models.CoseV001Schema{
			Message: p(msg),
			Data: &models.CoseV001SchemaData{
				Content: p(rawMsg),
			},
			PublicKey: p(pub),
		},
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

func mustContain(t *testing.T, want string, l []string) {
	for _, s := range l {
		if s == want {
			return
		}
	}
	t.Fatalf("list %v does not contain %s", l, want)
}
