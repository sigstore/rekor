//
// Copyright 2025 The Sigstore Authors.
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
	cryptox509 "crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekorx509 "github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

// Sample test data for benchmarking - using proper base64 signatures that match the regex

var sampleDSSEData = map[string]any{
	"proposedContent": map[string]any{
		"envelope":  `{"payload":"dGVzdA==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"MEUCIQDGk7qkVHnVahoEn4cLP9DRjxBArABCDEFGHIJKLMNOPQ=="}]}`,
		"verifiers": []string{"dGVzdFZlcmlmaWVyMQ==", "dGVzdFZlcmlmaWVyMg=="},
	},
	"signatures": []map[string]any{
		{
			"signature": "MEUCIQDGk7qkVHnVahoEn4cLP9DRjxBArABCDEFGHIJKLMNOPQ==",
			"verifier":  "dGVzdFZlcmlmaWVyMQ==",
		},
	},
	"envelopeHash": map[string]any{
		"algorithm": "sha256",
		"value":     "abc123",
	},
	"payloadHash": map[string]any{
		"algorithm": "sha256",
		"value":     "def456",
	},
}

// BenchmarkDecodeEntryMapstructure benchmarks the original mapstructure-based DecodeEntry
func BenchmarkDecodeEntryMapstructure(b *testing.B) {
	for b.Loop() {
		var dsseObj models.DSSEV001Schema
		err := types.DecodeEntry(sampleDSSEData, &dsseObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := dsseObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirect benchmarks the new direct JSON unmarshaling method
func BenchmarkDecodeEntryDirect(b *testing.B) {
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleDSSEData, &entry.DSSEObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}

		// Validate the result to ensure it's properly decoded
		if err := entry.DSSEObj.Validate(strfmt.Default); err != nil {
			b.Fatalf("Validation failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryMapstructureMemory benchmarks memory allocation for mapstructure
func BenchmarkDecodeEntryMapstructureMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var dsseObj models.DSSEV001Schema
		err := types.DecodeEntry(sampleDSSEData, &dsseObj)
		if err != nil {
			b.Fatalf("DecodeEntry failed: %v", err)
		}
	}
}

// BenchmarkDecodeEntryDirectMemory benchmarks memory allocation for direct method
func BenchmarkDecodeEntryDirectMemory(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		entry := &V001Entry{}
		err := DecodeEntry(sampleDSSEData, &entry.DSSEObj)
		if err != nil {
			b.Fatalf("DecodeEntryDirect failed: %v", err)
		}
	}
}

var benchmarkUnmarshalEntrySink *V001Entry

func BenchmarkV001EntryUnmarshal(b *testing.B) {
	for _, payloadSize := range []int{256 * 1024, 1024 * 1024, 32 * 1024 * 1024} {
		payloadSize := payloadSize
		b.Run(strconv.Itoa(payloadSize)+"B", func(b *testing.B) {
			pe := benchmarkProposedEntry(b, payloadSize)

			b.Run("BeforeVerifyAndDecode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					entry := &V001Entry{}
					if err := benchmarkUnmarshalBefore(entry, pe); err != nil {
						b.Fatalf("benchmarkUnmarshalBefore failed: %v", err)
					}
					benchmarkUnmarshalEntrySink = entry
				}
			})

			b.Run("AfterVerifyAndDecode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					entry := &V001Entry{}
					if err := entry.Unmarshal(pe); err != nil {
						b.Fatalf("Unmarshal failed: %v", err)
					}
					benchmarkUnmarshalEntrySink = entry
				}
			})
		})
	}
}

func benchmarkProposedEntry(tb testing.TB, payloadSize int) models.ProposedEntry {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	der, err := cryptox509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	payload, err := json.Marshal(map[string]any{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": []map[string]any{
			{
				"name": "artifact.tar.gz",
				"digest": map[string]string{
					"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				},
			},
		},
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": map[string]any{
			"materials": []map[string]any{
				{
					"uri": "git+https://github.com/sigstore/rekor",
					"digest": map[string]string{
						"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					},
				},
			},
			"buildConfig": string(bytes.Repeat([]byte("x"), payloadSize)),
		},
	})
	if err != nil {
		tb.Fatal(err)
	}

	env := benchmarkEnvelope(tb, key, payload)
	return &models.DSSE{
		APIVersion: conv.Pointer(APIVERSION),
		Spec: &models.DSSEV001Schema{
			ProposedContent: createRekorEnvelope(env, [][]byte{pub}),
		},
	}
}

func benchmarkEnvelope(tb testing.TB, key *ecdsa.PrivateKey, payload []byte) *ssldsse.Envelope {
	tb.Helper()

	s, err := signature.LoadECDSASigner(key, crypto.SHA256)
	if err != nil {
		tb.Fatal(err)
	}

	signer, err := ssldsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: s})
	if err != nil {
		tb.Fatal(err)
	}

	env, err := signer.SignPayload(context.Background(), in_toto.PayloadType, payload)
	if err != nil {
		tb.Fatal(err)
	}

	return env
}

func benchmarkUnmarshalBefore(v *V001Entry, pe models.ProposedEntry) error {
	it, ok := pe.(*models.DSSE)
	if !ok {
		return errors.New("cannot unmarshal non DSSE v0.0.1 type")
	}

	dsseObj := &models.DSSEV001Schema{}
	if err := DecodeEntry(it.Spec, dsseObj); err != nil {
		return err
	}

	if err := dsseObj.Validate(strfmt.Default); err != nil {
		return err
	}

	if dsseObj.ProposedContent == nil {
		if dsseObj.EnvelopeHash == nil || dsseObj.PayloadHash == nil || len(dsseObj.Signatures) == 0 {
			return errors.New("either proposedContent or envelopeHash, payloadHash, and signatures must be present")
		}
		v.DSSEObj = *dsseObj
		return nil
	}

	if dsseObj.EnvelopeHash != nil || dsseObj.PayloadHash != nil || len(dsseObj.Signatures) != 0 {
		return errors.New("either proposedContent or envelopeHash, payloadHash, and signatures must be present but not both")
	}

	env := &ssldsse.Envelope{}
	if dsseObj.ProposedContent.Envelope == nil {
		return errors.New("proposed content envelope is missing")
	}
	if err := json.Unmarshal([]byte(*dsseObj.ProposedContent.Envelope), env); err != nil {
		return err
	}

	if len(env.Signatures) == 0 {
		return errors.New("DSSE envelope must contain 1 or more signatures")
	}

	allPubKeyBytes := make([][]byte, 0, len(dsseObj.ProposedContent.Verifiers))
	for _, publicKey := range dsseObj.ProposedContent.Verifiers {
		if publicKey == nil {
			return errors.New("an invalid null verifier was provided in ProposedContent")
		}
		allPubKeyBytes = append(allPubKeyBytes, publicKey)
	}

	sigToKeyMap, decodedPayload, err := benchmarkVerifyEnvelopeBefore(allPubKeyBytes, env)
	if err != nil {
		return err
	}

	sortedSigs := make([]string, 0, len(sigToKeyMap))
	for sig := range sigToKeyMap {
		sortedSigs = append(sortedSigs, sig)
	}
	sort.Strings(sortedSigs)

	for i, sig := range sortedSigs {
		key := sigToKeyMap[sig]
		canonicalizedKey, err := key.CanonicalValue()
		if err != nil {
			return err
		}
		b64CanonicalizedKey := strfmt.Base64(canonicalizedKey)
		dsseObj.Signatures = append(dsseObj.Signatures, &models.DSSEV001SchemaSignaturesItems0{
			Signature: &sortedSigs[i],
			Verifier:  &b64CanonicalizedKey,
		})
	}

	if env.PayloadType == in_toto.PayloadType {
		var extract indexKeyExtract
		if err := json.Unmarshal(decodedPayload, &extract); err == nil {
			for _, s := range extract.Subject {
				for alg, ds := range s.Digest {
					v.extractedIndexKeys = append(v.extractedIndexKeys, alg+":"+ds)
				}
			}
			if extract.Predicate != nil {
				var materials materialsExtract
				if err := json.Unmarshal(extract.Predicate, &materials); err == nil {
					for _, m := range materials.Materials {
						for alg, ds := range m.Digest {
							v.extractedIndexKeys = append(v.extractedIndexKeys, alg+":"+ds)
						}
					}
				}
			}
		}
	}

	payloadHash := sha256.Sum256(decodedPayload)
	dsseObj.PayloadHash = &models.DSSEV001SchemaPayloadHash{
		Algorithm: conv.Pointer(models.DSSEV001SchemaPayloadHashAlgorithmSha256),
		Value:     conv.Pointer(fmt.Sprintf("%x", payloadHash[:])),
	}

	envelopeHash := sha256.Sum256([]byte(*dsseObj.ProposedContent.Envelope))
	dsseObj.EnvelopeHash = &models.DSSEV001SchemaEnvelopeHash{
		Algorithm: conv.Pointer(models.DSSEV001SchemaEnvelopeHashAlgorithmSha256),
		Value:     conv.Pointer(fmt.Sprintf("%x", envelopeHash[:])),
	}

	v.DSSEObj = *dsseObj
	v.env = env
	v.isInsertable = true
	v.env.Payload = ""
	v.DSSEObj.ProposedContent = nil

	return nil
}

func benchmarkVerifyEnvelopeBefore(allPubKeyBytes [][]byte, env *ssldsse.Envelope) (map[string]*rekorx509.PublicKey, []byte, error) {
	verifierBySig := make(map[string]*rekorx509.PublicKey)
	allSigs := make(map[string]struct{}, len(env.Signatures))
	for _, sig := range env.Signatures {
		allSigs[sig.Sig] = struct{}{}
	}

	for _, pubKeyBytes := range allPubKeyBytes {
		if len(allSigs) == 0 {
			break
		}

		key, err := rekorx509.NewPublicKey(bytes.NewReader(pubKeyBytes))
		if err != nil {
			return nil, nil, fmt.Errorf("could not parse public key as x509: %w", err)
		}

		vfr, err := signature.LoadVerifier(key.CryptoPubKey(), crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("could not load verifier: %w", err)
		}

		dsseVfr, err := ssldsse.NewEnvelopeVerifier(&sigdsse.VerifierAdapter{SignatureVerifier: vfr})
		if err != nil {
			return nil, nil, fmt.Errorf("could not use public key as a dsse verifier: %w", err)
		}

		accepted, err := dsseVfr.Verify(context.Background(), env)
		if err != nil {
			return nil, nil, fmt.Errorf("could not verify envelope: %w", err)
		}

		for _, accept := range accepted {
			delete(allSigs, accept.Sig.Sig)
			verifierBySig[accept.Sig.Sig] = key
		}
	}

	if len(allSigs) > 0 {
		return nil, nil, errors.New("all signatures must have a key that verifies it")
	}

	decodedPayload, err := env.DecodeB64Payload()
	if err != nil {
		return nil, nil, err
	}

	return verifierBySig, decodedPayload, nil
}
