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
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
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
	signer, err := dsse.NewEnvelopeSigner(
		&verifier{
			s: s,
		})
	if err != nil {
		t.Fatal(err)
	}
	dsseEnv, err := signer.SignPayload(context.Background(), "application/vnd.in-toto+json", payload)
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
	dsseEnv, err := signer.SignPayload(context.Background(), in_toto.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}

	return dsseEnv
}

func createRekorEnvelope(dsseEnv *dsse.Envelope, pub [][]byte) *models.IntotoV002SchemaContentEnvelope {
	env := &models.IntotoV002SchemaContentEnvelope{}
	b64 := strfmt.Base64([]byte(dsseEnv.Payload))
	env.Payload = b64
	env.PayloadType = &dsseEnv.PayloadType

	for i, sig := range dsseEnv.Signatures {
		keyBytes := strfmt.Base64(pub[i])
		sigBytes := strfmt.Base64([]byte(sig.Sig))
		env.Signatures = append(env.Signatures, &models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
			Keyid:     sig.KeyID,
			Sig:       &sigBytes,
			PublicKey: &keyBytes,
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
	keyBytes := strfmt.Base64("key")
	sigBytes := strfmt.Base64("sig")

	tests := []struct {
		env             *dsse.Envelope
		name            string
		it              *models.IntotoV002Schema
		wantErr         bool
		wantVerifierErr bool
	}{
		{
			name:            "empty",
			it:              &models.IntotoV002Schema{},
			wantErr:         true,
			wantVerifierErr: true,
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
			wantErr:         true,
			wantVerifierErr: true,
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
			wantErr:         false,
			wantVerifierErr: false,
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
			wantErr:         false,
			wantVerifierErr: false,
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
			wantErr:         true,
			wantVerifierErr: false,
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
			wantErr:         true,
			wantVerifierErr: true,
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
			wantErr:         false,
			wantVerifierErr: false,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "null array entry",
			it: &models.IntotoV002Schema{
				Content: &models.IntotoV002SchemaContent{
					Envelope: &models.IntotoV002SchemaContentEnvelope{
						Payload:     strfmt.Base64("cGF5bG9hZAo="),
						PayloadType: swag.String("payloadType"),
						Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
							{
								PublicKey: &keyBytes,
								Sig:       &sigBytes,
							},
							nil,
						},
					},
					Hash: &models.IntotoV002SchemaContentHash{
						Algorithm: swag.String(models.IntotoV002SchemaContentHashAlgorithmSha256),
						Value:     swag.String(envelopeHash(t, envelope(t, key, []byte(validPayload)))),
					},
				},
			},
			wantErr:         true,
			wantVerifierErr: true,
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

				if !tt.wantErr {
					if ok, err := v.Insertable(); !ok || err != nil {
						t.Errorf("unexpected error calling insertable on valid proposed entry: %v", err)
					}
				}

				want := []string{}
				for _, sig := range v.IntotoObj.Content.Envelope.Signatures {
					keyHash := sha256.Sum256(*sig.PublicKey)
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
				if ok, err := canonicalEntry.Insertable(); ok || err == nil {
					t.Errorf("unexpected success calling Insertable on entry created from canonicalized content")
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

				verifier, err := v.Verifier()
				if !tt.wantVerifierErr {
					if err != nil {
						t.Errorf("%v: unexpected error, got %v", tt.name, err)
					} else {
						pubV, _ := verifier.CanonicalValue()
						if !reflect.DeepEqual(pubV, pub) && !reflect.DeepEqual(pubV, pemBytes) {
							t.Errorf("verifier and public keys do not match: %v, %v", string(pubV), string(pub))
						}
					}
				} else {
					if err == nil {
						s, _ := verifier.CanonicalValue()
						t.Errorf("%v: expected error for %v, got %v", tt.name, string(s), err)
					}
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
					Materials: []common.ProvenanceMaterial{
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
					Materials: []common.ProvenanceMaterial{
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
				keyHash := sha256.Sum256(*sig.PublicKey)
				want = append(want, "sha256:"+hex.EncodeToString(keyHash[:]))
			}

			want = append(want, "sha256:"+hex.EncodeToString(payloadHash[:]))

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

func TestInsertable(t *testing.T) {
	type TestCase struct {
		caseDesc      string
		entry         V002Entry
		expectSuccess bool
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	env := envelope(t, key, []byte("payload"))
	keyBytes := strfmt.Base64([]byte("key"))
	sigBytes := strfmt.Base64([]byte("sig"))

	testCases := []TestCase{
		{
			caseDesc: "valid entry",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									PublicKey: &keyBytes,
									Sig:       &sigBytes,
								},
							},
						},
					},
				},
				env: *env,
			},
			expectSuccess: true,
		},
		{
			caseDesc: "valid entry but hasn't been parsed",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									PublicKey: &keyBytes,
									Sig:       &sigBytes,
								},
							},
						},
					},
				},
				env: dsse.Envelope{},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing sig",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									PublicKey: &keyBytes,
									//Sig:       strfmt.Base64([]byte("sig")),
								},
							},
						},
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing key",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									//PublicKey: strfmt.Base64([]byte("key")),
									Sig: &sigBytes,
								},
							},
						},
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "empty signatures",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures:  []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{},
							/*
								Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
									{
										PublicKey: strfmt.Base64([]byte("key")),
										Sig:       strfmt.Base64([]byte("sig")),
									},
								},
							*/
						},
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing payloadType",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							Payload: strfmt.Base64("payload"),
							//PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									PublicKey: &keyBytes,
									Sig:       &sigBytes,
								},
							},
						},
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing payload",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						Envelope: &models.IntotoV002SchemaContentEnvelope{
							//Payload:     strfmt.Base64("payload"),
							PayloadType: swag.String("payloadType"),
							Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
								{
									PublicKey: &keyBytes,
									Sig:       &sigBytes,
								},
							},
						},
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing envelope",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					Content: &models.IntotoV002SchemaContent{
						/*
							Envelope: &models.IntotoV002SchemaContentEnvelope{
								Payload:     strfmt.Base64("payload"),
								PayloadType: swag.String("payloadType"),
								Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
									{
										PublicKey: strfmt.Base64([]byte("key")),
										Sig:       strfmt.Base64([]byte("sig")),
									},
								},
							},
						*/
					},
				},
				env: *env,
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing content",
			entry: V002Entry{
				IntotoObj: models.IntotoV002Schema{
					/*
						Content: &models.IntotoV002SchemaContent{
							Envelope: &models.IntotoV002SchemaContentEnvelope{
								Payload:     strfmt.Base64("payload"),
								PayloadType: swag.String("payloadType"),
								Signatures: []*models.IntotoV002SchemaContentEnvelopeSignaturesItems0{
									{
										PublicKey: strfmt.Base64([]byte("key")),
										Sig:       strfmt.Base64([]byte("sig")),
									},
								},
							},
						},
					*/
				},
				env: *env,
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
