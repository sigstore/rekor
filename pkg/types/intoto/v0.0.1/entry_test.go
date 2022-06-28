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

package intoto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
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

func envelope(t *testing.T, k *ecdsa.PrivateKey, payload, payloadType string) string {

	s, err := signature.LoadECDSASigner(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := in_toto.NewDSSESigner(&verifier{
		s:   s,
		pub: k.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	dsseEnv, err := signer.SignPayload([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(dsseEnv)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestV001Entry_Unmarshal(t *testing.T) {
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
		SerialNumber:   big.NewInt(1),
		EmailAddresses: []string{"joe@schmoe.com"},
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	invalid, err := json.Marshal(dsse.Envelope{
		Payload: "hello",
		Signatures: []dsse.Signature{
			{
				Sig: string(strfmt.Base64("foobar")),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	validPayload := "hellothispayloadisvalid"

	tests := []struct {
		name                string
		want                models.IntotoV001Schema
		it                  *models.IntotoV001Schema
		wantErr             bool
		additionalIndexKeys []string
	}{
		{
			name:    "empty",
			it:      &models.IntotoV001Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.IntotoV001Schema{
				PublicKey: p(pub),
			},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.IntotoV001Schema{
				PublicKey: p([]byte("hello")),
			},
			wantErr: true,
		},
		{
			name: "valid intoto",
			it: &models.IntotoV001Schema{
				PublicKey: p(pub),
				Content: &models.IntotoV001SchemaContent{
					Envelope: envelope(t, key, validPayload, "application/vnd.in-toto+json"),
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid dsse but invalid intoto",
			it: &models.IntotoV001Schema{
				PublicKey: p(pub),
				Content: &models.IntotoV001SchemaContent{
					Envelope: envelope(t, key, validPayload, "text"),
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cert",
			it: &models.IntotoV001Schema{
				PublicKey: p([]byte(pemBytes)),
				Content: &models.IntotoV001SchemaContent{
					Envelope: envelope(t, priv, validPayload, "text"),
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
					},
				},
			},
			additionalIndexKeys: []string{"joe@schmoe.com"},
			wantErr:             false,
		},
		{
			name: "invalid",
			it: &models.IntotoV001Schema{
				PublicKey: p(pub),
				Content: &models.IntotoV001SchemaContent{
					Envelope: string(invalid),
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid key",
			it: &models.IntotoV001Schema{
				PublicKey: p([]byte("notavalidkey")),
				Content: &models.IntotoV001SchemaContent{
					Envelope: envelope(t, key, validPayload, "text"),
					Hash: &models.IntotoV001SchemaContentHash{
						Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V001Entry{}
			if tt.it.Content != nil {
				h := sha256.Sum256([]byte(tt.it.Content.Envelope))
				tt.it.Content.Hash.Algorithm = swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256)
				tt.it.Content.Hash.Value = swag.String(hex.EncodeToString(h[:]))
			}

			it := &models.Intoto{
				Spec: tt.it,
			}

			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}
				if err := v.validate(); err != nil {
					return err
				}
				keysWanted := tt.additionalIndexKeys
				if tt.it.PublicKey != nil {
					h := sha256.Sum256(*tt.it.PublicKey)
					keysWanted = append(keysWanted, fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:])))
				}
				payloadBytes, _ := v.env.DecodeB64Payload()
				payloadSha := sha256.Sum256(payloadBytes)
				payloadHash := hex.EncodeToString(payloadSha[:])
				// Always start with the hash
				keysWanted = append(keysWanted, "sha256:"+payloadHash)
				hashkey := strings.ToLower(fmt.Sprintf("%s:%s", *tt.it.Content.Hash.Algorithm, *tt.it.Content.Hash.Value))
				keysWanted = append(keysWanted, hashkey)
				if got, _ := v.IndexKeys(); !cmp.Equal(got, keysWanted, cmpopts.SortSlices(func(x, y string) bool { return x < y })) {
					t.Errorf("V001Entry.IndexKeys() = %v, want %v", got, keysWanted)
				}
				canonicalBytes, err := v.Canonicalize(context.Background())
				if err != nil {
					t.Errorf("error canonicalizing entry: %v", err)
				}

				pe, err := models.UnmarshalProposedEntry(bytes.NewReader(canonicalBytes), runtime.JSONConsumer())
				if err != nil {
					t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tt.name, err)
				}
				canonicalEntry, err := types.NewEntry(pe)
				if err != nil {
					t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tt.name, err)
				}
				canonicalV001 := canonicalEntry.(*V001Entry)
				fmt.Printf("%v", canonicalV001.IntotoObj.Content)
				if *canonicalV001.IntotoObj.Content.Hash.Value != *tt.it.Content.Hash.Value {
					t.Errorf("envelope hashes do not match post canonicalization: %v %v", *canonicalV001.IntotoObj.Content.Hash.Value, *tt.it.Content.Hash.Value)
				}
				if canonicalV001.AttestationKey() != "" && *canonicalV001.IntotoObj.Content.PayloadHash.Value != payloadHash {
					t.Errorf("payload hashes do not match post canonicalization: %v %v", canonicalV001.IntotoObj.Content.PayloadHash.Value, payloadHash)
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
	h := sha256.Sum256([]byte("foo"))
	dataSHA := hex.EncodeToString(h[:])
	hashkey := strings.ToLower(fmt.Sprintf("%s:%s", "sha256", dataSHA))

	tests := []struct {
		name      string
		statement in_toto.Statement
		want      []string
	}{
		{
			name: "standard",
			want: []string{hashkey},
			statement: in_toto.Statement{
				Predicate: "hello",
			},
		},
		{
			name: "subject",
			want: []string{"sha256:foo", hashkey},
			statement: in_toto.Statement{
				StatementHeader: in_toto.StatementHeader{
					Subject: []in_toto.Subject{
						{
							Name: "foo",
							Digest: map[string]string{
								"sha256": "foo",
							},
						},
					},
				},
				Predicate: "hello",
			},
		},
		{
			name: "slsa",
			want: []string{"sha256:bar", hashkey},
			statement: in_toto.Statement{
				Predicate: slsa.ProvenancePredicate{
					Materials: []slsa.ProvenanceMaterial{
						{
							URI: "foo",
							Digest: map[string]string{
								"sha256": "bar",
							}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.statement)
			if err != nil {
				t.Fatal(err)
			}
			payload := base64.StdEncoding.EncodeToString(b)
			v := V001Entry{
				IntotoObj: models.IntotoV001Schema{
					Content: &models.IntotoV001SchemaContent{
						Hash: &models.IntotoV001SchemaContentHash{
							Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
							Value:     swag.String(dataSHA),
						},
					},
				},
				env: dsse.Envelope{
					Payload:     payload,
					PayloadType: in_toto.PayloadType,
				},
			}
			sha := sha256.Sum256(b)
			// Always start with the hash
			want := []string{"sha256:" + hex.EncodeToString(sha[:])}
			want = append(want, tt.want...)
			got, _ := v.IndexKeys()
			sort.Strings(got)
			sort.Strings(want)
			if !cmp.Equal(got, want) {
				t.Errorf("V001Entry.IndexKeys() = %v, want %v", got, want)
			}
		})
	}
}

func TestIndexKeysNoContentHash(t *testing.T) {
	statement := in_toto.Statement{
		Predicate: "hello",
		StatementHeader: in_toto.StatementHeader{
			Subject: []in_toto.Subject{
				{
					Name: "myimage",
					Digest: slsa.DigestSet{
						"sha256": "mysha256digest",
					},
				},
			},
		},
	}
	b, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString(b)
	v := V001Entry{
		env: dsse.Envelope{
			Payload:     payload,
			PayloadType: in_toto.PayloadType,
		},
	}
	sha := sha256.Sum256(b)
	// Always start with the hash
	want := []string{"sha256:" + hex.EncodeToString(sha[:])}
	want = append(want, "sha256:mysha256digest")
	got, err := v.IndexKeys()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !cmp.Equal(got, want) {
		t.Errorf("V001Entry.IndexKeys() = %v, want %v", got, want)
	}
}
