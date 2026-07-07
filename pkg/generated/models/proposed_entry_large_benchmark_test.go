package models

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	cryptox509 "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"sync"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/in-toto/in-toto-golang/in_toto"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	sigdsse "github.com/sigstore/sigstore/pkg/signature/dsse"
)

// BenchmarkUnmarshalProposedEntryLarge exercises the unmarshal path with real,
// ECDSA-signed DSSE envelopes wrapping an in-toto Statement whose predicate
// carries a large opaque field. The same underlying signed envelope is wrapped
// two ways so DSSE and intoto v0.0.2 can be compared apples-to-apples.
//
// Sizes below refer to the raw predicate opaque field; the resulting
// ProposedEntry JSON is larger due to base64 inflation of the envelope +
// verifier PEM. Only DSSE and intoto v0.0.2 vary in size — hashedrekord bodies
// are always tiny in production (real ECDSA sigs are ~72 B), so hashedrekord
// gets a single realistic case built with a genuine ECDSA-P256 signature.
// Fixtures are generated once per process at first use.
func BenchmarkUnmarshalProposedEntryLarge(b *testing.B) {
	sizes := []int{256 * 1024, 1024 * 1024, 32 * 1024 * 1024}
	consumer := runtime.JSONConsumer()

	for _, sz := range sizes {
		f := largeFixtureCache.get(b, sz)
		sizeName := strconv.Itoa(sz) + "B"

		b.Run("dsse/"+sizeName, func(b *testing.B) {
			runUnmarshalBench(b, f.dsseBody, consumer)
		})

		b.Run("intoto_v002/"+sizeName, func(b *testing.B) {
			runUnmarshalBench(b, f.intotoV002Body, consumer)
		})
	}

	b.Run("hashedrekord", func(b *testing.B) {
		runUnmarshalBench(b, hashedRekordFixture(b), consumer)
	})
}

func runUnmarshalBench(b *testing.B, body []byte, consumer runtime.Consumer) {
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		pe, err := UnmarshalProposedEntry(bytes.NewReader(body), consumer)
		if err != nil {
			b.Fatalf("UnmarshalProposedEntry failed: %v", err)
		}
		benchmarkProposedEntrySink = pe
	}
}

// TestLargeSignedProposedEntriesBuild ensures the fixture generators produce
// ProposedEntries the unmarshal path accepts. Keeps the crypto setup on the
// tested path so a broken helper doesn't silently no-op the benchmark.
func TestLargeSignedProposedEntriesBuild(t *testing.T) {
	f := largeFixtureCache.get(t, 4096)

	for _, tc := range []struct {
		name     string
		body     []byte
		wantKind string
	}{
		{"dsse", f.dsseBody, "dsse"},
		{"intoto_v002", f.intotoV002Body, "intoto"},
		{"hashedrekord", hashedRekordFixture(t), "hashedrekord"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pe, err := UnmarshalProposedEntry(bytes.NewReader(tc.body), runtime.JSONConsumer())
			if err != nil {
				t.Fatalf("UnmarshalProposedEntry: %v", err)
			}
			if pe.Kind() != tc.wantKind {
				t.Fatalf("Kind() = %q, want %q", pe.Kind(), tc.wantKind)
			}
		})
	}
}

// largeFixture holds a signed DSSE envelope pre-wrapped as two ProposedEntry
// shapes so DSSE and intoto v0.0.2 benchmarks share the same crypto material.
type largeFixture struct {
	dsseBody       []byte
	intotoV002Body []byte
}

type fixtureCache struct {
	mu     sync.Mutex
	byLen  map[int]*sync.Once
	values map[int]*largeFixture
	errs   map[int]error
}

var largeFixtureCache = &fixtureCache{
	byLen:  map[int]*sync.Once{},
	values: map[int]*largeFixture{},
	errs:   map[int]error{},
}

func (c *fixtureCache) get(tb testing.TB, sz int) *largeFixture {
	tb.Helper()

	c.mu.Lock()
	once, ok := c.byLen[sz]
	if !ok {
		once = &sync.Once{}
		c.byLen[sz] = once
	}
	c.mu.Unlock()

	once.Do(func() {
		f, err := buildLargeFixture(sz)
		c.mu.Lock()
		c.values[sz] = f
		c.errs[sz] = err
		c.mu.Unlock()
	})

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.errs[sz]; err != nil {
		tb.Fatalf("build large fixture (size=%d): %v", sz, err)
	}
	return c.values[sz]
}

func buildLargeFixture(payloadSize int) (*largeFixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	der, err := cryptox509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	payload, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"subject": []map[string]any{
			{
				"name":   "artifact.tar.gz",
				"digest": map[string]string{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
		},
		"predicate": map[string]any{
			"builder":   map[string]any{"id": "https://github.com/sigstore/rekor/benchmark"},
			"buildType": "https://example.com/build",
			"materials": []map[string]any{{
				"uri":    "git+https://github.com/sigstore/rekor",
				"digest": map[string]string{"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
			}},
			// Opaque field sized to the caller's request; base64-encoding
			// keeps it a valid JSON string and roughly the requested length.
			"buildConfig": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, payloadSize)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}

	signer, err := signature.LoadECDSASigner(key, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("load ECDSA signer: %w", err)
	}
	envSigner, err := ssldsse.NewEnvelopeSigner(&sigdsse.SignerAdapter{SignatureSigner: signer})
	if err != nil {
		return nil, fmt.Errorf("new envelope signer: %w", err)
	}
	env, err := envSigner.SignPayload(context.Background(), in_toto.PayloadType, payload)
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	dsseBody, err := wrapAsDSSEProposedEntry(envJSON, pubPEM)
	if err != nil {
		return nil, fmt.Errorf("wrap DSSE: %w", err)
	}
	intotoBody, err := wrapAsIntotoV002ProposedEntry(env, envJSON, pubPEM, payload)
	if err != nil {
		return nil, fmt.Errorf("wrap intoto v0.0.2: %w", err)
	}

	return &largeFixture{
		dsseBody:       dsseBody,
		intotoV002Body: intotoBody,
	}, nil
}

func wrapAsDSSEProposedEntry(envJSON, pubPEM []byte) ([]byte, error) {
	return json.Marshal(map[string]any{
		"kind":       "dsse",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"proposedContent": map[string]any{
				"envelope":  string(envJSON),
				"verifiers": []string{base64.StdEncoding.EncodeToString(pubPEM)},
			},
		},
	})
}

// wrapAsIntotoV002ProposedEntry produces an intoto v0.0.2 body. Envelope is a
// nested JSON object (not a string like DSSE), each signature carries a
// base64-encoded PEM public key, and content includes hash + payloadHash.
func wrapAsIntotoV002ProposedEntry(env *ssldsse.Envelope, envJSON, pubPEM, payload []byte) ([]byte, error) {
	sigs := make([]map[string]any, 0, len(env.Signatures))
	for _, s := range env.Signatures {
		sigs = append(sigs, map[string]any{
			"keyid":     s.KeyID,
			"sig":       s.Sig,
			"publicKey": base64.StdEncoding.EncodeToString(pubPEM),
		})
	}
	envHash := sha256.Sum256(envJSON)
	payloadHash := sha256.Sum256(payload)
	return json.Marshal(map[string]any{
		"kind":       "intoto",
		"apiVersion": "0.0.2",
		"spec": map[string]any{
			"content": map[string]any{
				"envelope": map[string]any{
					"payload":     env.Payload,
					"payloadType": env.PayloadType,
					"signatures":  sigs,
				},
				"hash":        map[string]any{"algorithm": "sha256", "value": fmt.Sprintf("%x", envHash[:])},
				"payloadHash": map[string]any{"algorithm": "sha256", "value": fmt.Sprintf("%x", payloadHash[:])},
			},
		},
	})
}

// hashedRekordFixture returns a ProposedEntry carrying a real ECDSA-P256
// signature over a small artifact. Produced once per process; body size is
// whatever a real signature + PEM comes to (~500 B), because hashedrekord
// payloads don't scale in production.
func hashedRekordFixture(tb testing.TB) []byte {
	tb.Helper()
	hashedRekordOnce.Do(func() {
		hashedRekordBody, hashedRekordErr = buildHashedRekordFixture()
	})
	if hashedRekordErr != nil {
		tb.Fatalf("build hashedrekord fixture: %v", hashedRekordErr)
	}
	return hashedRekordBody
}

var (
	hashedRekordOnce sync.Once
	hashedRekordBody []byte
	hashedRekordErr  error
)

func buildHashedRekordFixture() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	der, err := cryptox509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal PKIX public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	artifact := []byte("rekor benchmark artifact")
	sum := sha256.Sum256(artifact)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("sign artifact hash: %w", err)
	}

	return json.Marshal(map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     fmt.Sprintf("%x", sum[:]),
				},
			},
			"signature": map[string]any{
				"content": base64.StdEncoding.EncodeToString(sig),
				"publicKey": map[string]any{
					"content": base64.StdEncoding.EncodeToString(pubPEM),
				},
			},
		},
	})
}
