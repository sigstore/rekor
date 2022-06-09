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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/sigstore/rekor/pkg/generated/models"
	sigx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/spf13/viper"
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
			name: "missing data",
			it: &models.CoseV001Schema{
				PublicKey: p(pub),
			},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte("hello")),
			},
			wantErr: true,
		},
		{
			name: "valid",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p(pub),
				Message:   msg,
			},
			wantErr: false,
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
			wantErr: false,
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
			wantErr: true,
		},
		{
			name: "invalid envelope",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte(pemBytes)),
				Message:   []byte("hello"),
			},
			wantErr: true,
		},
		{
			name: "cert",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte(pemBytes)),
				Message:   msg,
			},
			wantErr: false,
		},
		{
			name: "invalid key",
			it: &models.CoseV001Schema{
				Data:      &models.CoseV001SchemaData{},
				PublicKey: p([]byte("notavalidkey")),
				Message:   []byte("hello"),
			},
			wantErr: true,
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
		})
	}
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
		att := v.Attestation()
		if len(att) != 0 {
			t.Errorf("Attestation returned")
		}
	})

	t.Run("with storage", func(t *testing.T) {
		// Need to trick viper to update config so we can return
		// an attestation
		os.Setenv("MAX_ATTESTATION_SIZE", "1048576")
		viper.AutomaticEnv()
		v := &V001Entry{
			CoseObj: models.CoseV001Schema{},
		}
		if err := v.Unmarshal(it); err != nil {
			t.Errorf("V001Entry.Unmarshal() error = %v", err)
		}
		att := v.Attestation()
		if len(att) != len(msg) {
			t.Errorf("Wrong attestation returned")
		}
		for i := range att {
			if att[i] != msg[i] {
				t.Errorf("Wrong attestation returned")
				return
			}
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
