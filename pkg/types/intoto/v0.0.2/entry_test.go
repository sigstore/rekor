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
	if reflect.TypeOf(entry) != reflect.ValueOf(&V002Entry{}).Type() {
		t.Errorf("invalid type returned from NewEntry: %T", entry)
	}
}

func envelope(t *testing.T, k *ecdsa.PrivateKey, payload []byte) *dsse.Envelope {

	s, err := signature.LoadECDSASigner(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := in_toto.NewDSSESigner(
		&verifier{
			s: s,
		})
	if err != nil {
		t.Fatal(err)
	}
	dsseEnv, err := signer.SignPayload(payload)
	if err != nil {
		t.Fatal(err)
	}

	return dsseEnv
}

func multiSignEnvelope(t *testing.T, k []*ecdsa.PrivateKey, payload []byte) *dsse.Envelope {
	evps := []*verifier{}
	for _, key := range k {
		s, err := signature.LoadECDSASigner(key, crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		evps = append(evps, &verifier{
			s: s,
		})
	}

	signer, err := dsse.NewMultiEnvelopeSigner(2, evps[0], evps[1])
	if err != nil {
		t.Fatal(err)
	}
	dsseEnv, err := signer.SignPayload(in_toto.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}

	return dsseEnv
}

func createRekorEnvelope(dsseEnv *dsse.Envelope, pub [][]byte) *models.IntotoV002SchemaContentEnvelope {

	env := &models.IntotoV002SchemaContentEnvelope{}
	env.Payload = dsseEnv.Payload
	env.PayloadType = &dsseEnv.PayloadType

	for i, sig := range dsseEnv.Signatures {
		env.Signatures = append(env.Signatures, &models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
			Keyid:     sig.KeyID,
			Sig:       sig.Sig,
			PublicKey: strfmt.Base64(pub[i]),
		})
	}
	return env
}

func envelopeHash(t *testing.T, dsseEnv *dsse.Envelope) string {
	val, err := json.Marshal(dsseEnv)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(val)
	return hex.EncodeToString(h[:])
}

func TestV002Entry_Unmarshal(t *testing.T) {
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
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	invalid := dsse.Envelope{
		Payload: "hello",
		Signatures: []dsse.Signature{
			{
				Sig: string(strfmt.Base64("foobar")),
			},
		},
	}

	validPayload := "hellothispayloadisvalid"

	doubleEncodedEnvelope := createRekorEnvelope(envelope(t, key, []byte(validPayload)), [][]byte{pub})
	doubleEncodedPayload := base64.StdEncoding.EncodeToString([]byte(doubleEncodedEnvelope.Payload))
	doubleEncodedEnvelope.Payload = doubleEncodedPayload
	doubleEncodedSig := base64.StdEncoding.EncodeToString([]byte(doubleEncodedEnvelope.Signatures[0].Sig))
	doubleEncodedEnvelope.Signatures[0].Sig = doubleEncodedSig

	tests := []struct {
		env     *dsse.Envelope
		name    string
		it      *models.IntotoV002Schema
		wantErr bool
	}{
		{
			name:    "empty",
			it:      &models.IntotoV002Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
					},
				},
			},
			wantErr: true,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "valid",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: createRekorEnvelope(envelope(t, key, []byte(validPayload)), [][]byte{pub}),
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, envelope(t, key, []byte(validPayload)))),
					},
				},
			},
			wantErr: false,
		},
		{
			env:  envelope(t, priv, []byte(validPayload)),
			name: "cert",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: createRekorEnvelope(envelope(t, priv, []byte(validPayload)), [][]byte{pemBytes}),
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, envelope(t, priv, []byte(validPayload)))),
					},
				},
			},
			wantErr: false,
		},
		{
			env:  &invalid,
			name: "invalid",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: createRekorEnvelope(&invalid, [][]byte{pub}),
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, &invalid)),
					},
				},
			},
			wantErr: true,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "invalid key",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: createRekorEnvelope(envelope(t, key, []byte(validPayload)), [][]byte{[]byte("notavalidkey")}),
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, envelope(t, key, []byte(validPayload)))),
					},
				},
			},
			wantErr: true,
		},
		{
			env:  multiSignEnvelope(t, []*ecdsa.PrivateKey{key, priv}, []byte(validPayload)),
			name: "multi-key",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: createRekorEnvelope(multiSignEnvelope(t, []*ecdsa.PrivateKey{key, priv}, []byte(validPayload)), [][]byte{pub, pemBytes}),
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, multiSignEnvelope(t, []*ecdsa.PrivateKey{key, priv}, []byte(validPayload)))),
					},
				},
			},
			wantErr: false,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "double base64 encoded envelope (testing backwards compat with v0.12.x and v1.0.0",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: doubleEncodedEnvelope,
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, envelope(t, priv, []byte(validPayload)))),
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V002Entry{}

			it := &models.Intoto{
				Spec: tt.it,
			}

			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}
				want := []string{}
				for _, sig := range v.IntotoObj.Content.Envelope.Signatures {
					keyHash := sha256.Sum256(sig.PublicKey)
					want = append(want, "sha256:"+hex.EncodeToString(keyHash[:]))
				}
				decodedPayload, err := base64.StdEncoding.DecodeString(tt.env.Payload)
				if err != nil {
					return fmt.Errorf("could not decode envelope payload: %w", err)
				}
				h := sha256.Sum256(decodedPayload)
				want = append(want, "sha256:"+hex.EncodeToString(h[:]))

				if !reflect.DeepEqual(v.AttestationKey(), "sha256:"+hex.EncodeToString(h[:])) {
					t.Errorf("V002Entry.AttestationKey() = %v, want %v", v.AttestationKey(), "sha256:"+hex.EncodeToString(h[:]))
				}

				hashkey := strings.ToLower(fmt.Sprintf("%s:%s", *tt.it.Content.Hash.Algorithm, *tt.it.Content.Hash.Value))
				want = append(want, hashkey)
				got, _ := v.IndexKeys()
				sort.Strings(got)
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("V002Entry.IndexKeys() = %v, want %v", got, want)
				}
				payloadBytes, _ := v.env.DecodeB64Payload()
				payloadSha := sha256.Sum256(payloadBytes)
				payloadHash := hex.EncodeToString(payloadSha[:])

				canonicalBytes, err := v.Canonicalize(context.Background())
				if err != nil {
					t.Errorf("error canonicalizing entry: %v", err)
				}

				pe, err := models.UnmarshalProposedEntry(bytes.NewReader(canonicalBytes), runtime.JSONConsumer())
				if err != nil {
					t.Errorf("unexpected err from Unmarshalling canonicalized entry for '%v': %v", tt.name, err)
				}
				canonicalEntry, err := types.UnmarshalEntry(pe)
				if err != nil {
					t.Errorf("unexpected err from type-specific unmarshalling for '%v': %v", tt.name, err)
				}
				canonicalV002 := canonicalEntry.(*V002Entry)
				fmt.Printf("%v", canonicalV002.IntotoObj.Content)
				if *canonicalV002.IntotoObj.Content.Hash.Value != *tt.it.Content.Hash.Value {
					t.Errorf("envelope hashes do not match post canonicalization: %v %v", *canonicalV002.IntotoObj.Content.Hash.Value, *tt.it.Content.Hash.Value)
				}
				if canonicalV002.AttestationKey() != "" && *canonicalV002.IntotoObj.Content.PayloadHash.Value != payloadHash {
					t.Errorf("payload hashes do not match post canonicalization: %v %v", canonicalV002.IntotoObj.Content.PayloadHash.Value, payloadHash)
				}
				canonicalIndexKeys, _ := canonicalV002.IndexKeys()
				if !cmp.Equal(got, canonicalIndexKeys, cmpopts.SortSlices(func(x, y string) bool { return x < y })) {
					t.Errorf("index keys from hydrated object do not match those generated from canonicalized (and re-hydrated) object: %v %v", got, canonicalIndexKeys)
				}

				return nil
			}
			if err := uv(); (err != nil) != tt.wantErr {
				t.Errorf("V002Entry.Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestV002Entry_IndexKeys(t *testing.T) {
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

	tests := []struct {
		name      string
		statement in_toto.Statement
		want      []string
	}{
		{
			name: "standard",
			want: []string{},
			statement: in_toto.Statement{
				Predicate: "hello",
			},
		},
		{
			name: "subject",
			want: []string{"sha256:foo"},
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
			want: []string{"sha256:bar"},
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
		{
			name: "slsa wit header",
			want: []string{"sha256:foo", "sha256:bar"},
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
			payloadHash := sha256.Sum256(b)
			v := V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: createRekorEnvelope(envelope(t, key, b), [][]byte{pub}),
						Hash: &models.IntotoV002SchemaContentHash{
							Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
							Value:     swag.String(envelopeHash(t, envelope(t, key, b))),
						},
						PayloadHash: &models.IntotoV002SchemaContentPayloadHash{
							Algorithm: swag.String(models.IntotoV001SchemaContentHashAlgorithmSha256),
							Value:     swag.String(hex.EncodeToString(payloadHash[:])),
						},
					},
				},
				env: *envelope(t, key, b),
			}
			want := []string{}
			for _, sig := range v.IntotoObj.Content.Envelope.Signatures {
				keyHash := sha256.Sum256(sig.PublicKey)
				want = append(want, "sha256:"+hex.EncodeToString(keyHash[:]))
			}

			want = append(want, "sha256:"+hex.EncodeToString(payloadHash[:]))

			hashkey := strings.ToLower("sha256:" + *v.IntotoObj.Content.Hash.Value)
			want = append(want, hashkey)
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
