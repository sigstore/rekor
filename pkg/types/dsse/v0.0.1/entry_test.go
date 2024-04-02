//
// Copyright 2023 The Sigstore Authors.
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

package dsse

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
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
	slsaCommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
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

type ecdsaSignature struct {
	R, S *big.Int
}

// From https://github.com/tink-crypto/tink/blob/43c17d490a6c8391bb5384278963cb59f4b65495/go/signature/subtle/encoding.go#L62
func ieeeSignatureSize(curveName string) (int, error) {
	switch curveName {
	case elliptic.P256().Params().Name:
		return 64, nil
	case elliptic.P384().Params().Name:
		return 96, nil
	case elliptic.P521().Params().Name:
		return 132, nil
	default:
		return 0, fmt.Errorf("ieeeP1363 unsupported curve name: %q", curveName)
	}
}

// From https://github.com/tink-crypto/tink/blob/43c17d490a6c8391bb5384278963cb59f4b65495/go/signature/subtle/encoding.go#L75
func ieeeP1363Encode(sig *ecdsaSignature, curveName string) ([]byte, error) {
	sigSize, err := ieeeSignatureSize(curveName)
	if err != nil {
		return nil, err
	}

	enc := make([]byte, sigSize)

	// sigR and sigS must be half the size of the signature. If not, we need to pad them with zeros.
	offset := 0
	if len(sig.R.Bytes()) < (sigSize / 2) {
		offset += (sigSize / 2) - len(sig.R.Bytes())
	}
	// Copy sigR after any zero-padding.
	copy(enc[offset:], sig.R.Bytes())

	// Skip the bytes of sigR.
	offset = sigSize / 2
	if len(sig.S.Bytes()) < (sigSize / 2) {
		offset += (sigSize / 2) - len(sig.S.Bytes())
	}
	// Copy sigS after sigR and any zero-padding.
	copy(enc[offset:], sig.S.Bytes())

	return enc, nil
}

func envelope(t *testing.T, k *ecdsa.PrivateKey, payload []byte) *dsse.Envelope {

	s, err := signature.LoadECDSASigner(k, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := dsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{
		SignatureSigner: s,
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
	evps := []*sigdsse.SignerAdapter{}
	for _, key := range k {
		s, err := signature.LoadECDSASigner(key, crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		evps = append(evps, &sigdsse.SignerAdapter{
			SignatureSigner: s,
		})
	}

	signer, err := dsse.NewEnvelopeSigner(evps[0], evps[1])
	if err != nil {
		t.Fatal(err)
	}
	dsseEnv, err := signer.SignPayload(context.Background(), in_toto.PayloadType, payload)
	if err != nil {
		t.Fatal(err)
	}

	return dsseEnv
}

func createRekorEnvelope(dsseEnv *dsse.Envelope, pub [][]byte) *models.DSSEV001SchemaProposedContent {

	envelopeBytes, _ := json.Marshal(dsseEnv)
	proposedContent := &models.DSSEV001SchemaProposedContent{
		Envelope: swag.String(string(envelopeBytes)),
	}
	for _, key := range pub {
		proposedContent.Verifiers = append(proposedContent.Verifiers, strfmt.Base64(key))
	}
	return proposedContent
}

// transformECDSASignatures converts ASN.1 encoded ECDSA signatures (SEQ{r, s})
// to IEEE P1363 encoding (r||s)
func transformECDSASignatures(t *testing.T, k *ecdsa.PrivateKey, dsseEnv *dsse.Envelope) *dsse.Envelope {
	sigs := dsseEnv.Signatures
	var newSigs []dsse.Signature
	for _, b64sig := range sigs {
		sig, err := base64.StdEncoding.DecodeString(b64sig.Sig)
		if err != nil {
			t.Fatal(err)
		}
		ecdsaSig := ecdsaSignature{}
		if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
			t.Fatal(err)
		}
		ieeeP1363Sig, err := ieeeP1363Encode(&ecdsaSig, k.Params().Name)
		if err != nil {
			t.Fatal(err)
		}
		newSigs = append(newSigs, dsse.Signature{KeyID: b64sig.KeyID, Sig: base64.StdEncoding.EncodeToString(ieeeP1363Sig)})
	}
	dsseEnv.Signatures = newSigs
	return dsseEnv
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

	validEnv := envelope(t, key, []byte("payload"))
	validEnvBytes, _ := json.Marshal(validEnv)

	validPayload := "hellothispayloadisvalid"

	tests := []struct {
		env     *dsse.Envelope
		name    string
		it      *models.DSSEV001Schema
		wantErr bool
	}{
		{
			name:    "empty",
			it:      &models.DSSEV001Schema{},
			wantErr: true,
		},
		{
			name: "missing envelope",
			it: &models.DSSEV001Schema{
				ProposedContent: &models.DSSEV001SchemaProposedContent{},
			},
			wantErr: true,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "valid",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(envelope(t, key, []byte(validPayload)), [][]byte{pub}),
			},
			wantErr: false,
		},
		{
			env:  envelope(t, priv, []byte(validPayload)),
			name: "cert",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(envelope(t, priv, []byte(validPayload)), [][]byte{pemBytes}),
			},
			wantErr: false,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "key with IEEE P1361 sig",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(transformECDSASignatures(t, key, envelope(t, key, []byte(validPayload))), [][]byte{pub}),
			},
			wantErr: false,
		},
		{
			env:  envelope(t, priv, []byte(validPayload)),
			name: "cert with IEEE P1361 sig",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(transformECDSASignatures(t, priv, envelope(t, priv, []byte(validPayload))), [][]byte{pemBytes}),
			},
			wantErr: false,
		},
		{
			env:  &invalid,
			name: "invalid",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(&invalid, [][]byte{pub}),
			},
			wantErr: true,
		},
		{
			env:  envelope(t, key, []byte(validPayload)),
			name: "invalid key",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(envelope(t, key, []byte(validPayload)), [][]byte{[]byte("notavalidkey")}),
			},
			wantErr: true,
		},
		{
			env:  multiSignEnvelope(t, []*ecdsa.PrivateKey{key, priv}, []byte(validPayload)),
			name: "multi-key",
			it: &models.DSSEV001Schema{
				ProposedContent: createRekorEnvelope(multiSignEnvelope(t, []*ecdsa.PrivateKey{key, priv}, []byte(validPayload)), [][]byte{pub, pemBytes}),
			},
			wantErr: false,
		},
		{
			env:  validEnv,
			name: "null verifier in array",
			it: &models.DSSEV001Schema{
				ProposedContent: &models.DSSEV001SchemaProposedContent{
					Envelope:  swag.String(string(validEnvBytes)),
					Verifiers: []strfmt.Base64{pub, nil},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &V001Entry{}

			it := &models.DSSE{
				Spec: tt.it,
			}

			var uv = func() error {
				if err := v.Unmarshal(it); err != nil {
					return err
				}

				if !tt.wantErr {
					if ok, err := v.Insertable(); !ok || err != nil {
						return fmt.Errorf("unexpected error calling Insertable: %w", err)
					}
				}
				want := []string{}
				for _, sig := range v.DSSEObj.Signatures {
					keyHash := sha256.Sum256(*sig.Verifier)
					want = append(want, "sha256:"+hex.EncodeToString(keyHash[:]))
				}
				decodedPayload, err := base64.StdEncoding.DecodeString(tt.env.Payload)
				if err != nil {
					return fmt.Errorf("could not decode envelope payload: %w", err)
				}
				h := sha256.Sum256(decodedPayload)
				want = append(want, "sha256:"+hex.EncodeToString(h[:]))

				envHashBytes := sha256.Sum256([]byte(*tt.it.ProposedContent.Envelope))
				envHash := hex.EncodeToString(envHashBytes[:])

				hashkey := strings.ToLower(fmt.Sprintf("sha256:%s", envHash))
				want = append(want, hashkey)
				got, _ := v.IndexKeys()
				sort.Strings(got)
				sort.Strings(want)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("V001Entry.IndexKeys() = %v, want %v", got, want)
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
				canonicalV001 := canonicalEntry.(*V001Entry)
				if ok, err := canonicalV001.Insertable(); ok || err == nil {
					t.Errorf("unexpected success testing Insertable against entry created from canonicalized content")
				}
				if *canonicalV001.DSSEObj.EnvelopeHash.Value != envHash {
					t.Errorf("envelope hashes do not match post canonicalization: %v %v", *canonicalV001.DSSEObj.EnvelopeHash.Value, envHash)
				}
				if *canonicalV001.DSSEObj.PayloadHash.Value != payloadHash {
					t.Errorf("payload hashes do not match post canonicalization: %v %v", canonicalV001.DSSEObj.PayloadHash.Value, payloadHash)
				}
				canonicalIndexKeys, _ := canonicalV001.IndexKeys()
				if !cmp.Equal(got, canonicalIndexKeys, cmpopts.SortSlices(func(x, y string) bool { return x < y })) {
					t.Errorf("index keys from hydrated object do not match those generated from canonicalized (and re-hydrated) object: %v %v", got, canonicalIndexKeys)
				}

				hash, err := canonicalV001.ArtifactHash()
				expectedHash := sha256.Sum256([]byte(validPayload))
				if err != nil {
					t.Errorf("unexpected failure with ArtifactHash: %v", err)
				} else if hash != "sha256:"+hex.EncodeToString(expectedHash[:]) {
					t.Errorf("unexpected match with ArtifactHash: %s", hash)
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
					Materials: []slsaCommon.ProvenanceMaterial{
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
					Materials: []slsaCommon.ProvenanceMaterial{
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
			pe := &models.DSSE{
				APIVersion: swag.String(APIVERSION),
				Spec: &models.DSSEV001Schema{
					ProposedContent: createRekorEnvelope(envelope(t, key, b), [][]byte{pub}),
				},
			}
			v := V001Entry{}
			if err := v.Unmarshal(pe); err != nil {
				t.Error(err)
			}
			want := []string{}
			for _, sig := range v.DSSEObj.Signatures {
				keyHash := sha256.Sum256(*sig.Verifier)
				want = append(want, "sha256:"+hex.EncodeToString(keyHash[:]))
			}
			decodedPayload, _ := base64.StdEncoding.DecodeString(v.env.Payload)
			h := sha256.Sum256(decodedPayload)
			want = append(want, "sha256:"+hex.EncodeToString(h[:]))

			envHashBytes := sha256.Sum256([]byte(*v.DSSEObj.ProposedContent.Envelope))
			envHash := hex.EncodeToString(envHashBytes[:])

			hashkey := strings.ToLower(fmt.Sprintf("sha256:%s", envHash))
			want = append(want, hashkey)
			want = append(want, tt.want...)
			got, err := v.IndexKeys()
			if err != nil {
				t.Error(err)
			}
			sort.Strings(got)
			sort.Strings(want)
			if !cmp.Equal(got, want, cmpopts.EquateEmpty()) {
				t.Errorf("V001Entry.IndexKeys() = %v, want %v", got, want)
			}
		})
	}
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
				DSSEObj: models.DSSEV001Schema{
					ProposedContent: &models.DSSEV001SchemaProposedContent{
						Envelope: swag.String("envelope"),
						Verifiers: []strfmt.Base64{
							[]byte("keys"),
						},
					},
				},
			},
			expectSuccess: true,
		},
		{
			caseDesc: "missing public keys",
			entry: V001Entry{
				DSSEObj: models.DSSEV001Schema{
					ProposedContent: &models.DSSEV001SchemaProposedContent{
						Envelope: swag.String("envelope"),
						/*
							Verifiers: []strfmt.Base64{
								[]byte("keys"),
							},
						*/
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing envelope",
			entry: V001Entry{
				DSSEObj: models.DSSEV001Schema{
					ProposedContent: &models.DSSEV001SchemaProposedContent{
						//Envelope: swag.String("envelope"),
						Verifiers: []strfmt.Base64{
							[]byte("keys"),
						},
					},
				},
			},
			expectSuccess: false,
		},
		{
			caseDesc: "missing proposed content obj",
			entry: V001Entry{
				DSSEObj: models.DSSEV001Schema{
					/*
						ProposedContent: &models.DSSEV001SchemaProposedContent{
							Envelope: swag.String("envelope"),
							Verifiers: []strfmt.Base64{
								[]byte("keys"),
							},
						},
					*/
				},
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

func TestCanonicalizeHandlesInvalidInput(t *testing.T) {
	v := &V001Entry{}
	v.DSSEObj.Signatures = []*models.DSSEV001SchemaSignaturesItems0{{Signature: nil}, {Signature: nil}}
	_, err := v.Canonicalize(context.TODO())
	if err == nil {
		t.Fatalf("expected error canonicalizing invalid input")
	}
}
