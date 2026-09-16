//
// Copyright 2026 The Sigstore Authors.
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

package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestFilterEntryTypes_EmptyRequestedReturnsNothing(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord":       {"0.0.1"},
		"intoto":       {"0.0.1", "0.0.2"},
		"hashedrekord": {"0.0.1"},
	}

	got, err := filterEntryTypes(allEntries, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil requested should return no entries")
	}

	got, err = filterEntryTypes(allEntries, []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty slice requested should return no entries")
	}
}

func TestFilterEntryTypes_SubsetPreservesVersions(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord":       {"0.0.1"},
		"intoto":       {"0.0.1", "0.0.2"},
		"hashedrekord": {"0.0.1"},
	}

	got, err := filterEntryTypes(allEntries, []string{"rekord", "intoto"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"rekord", "intoto"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("subset filter mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestFilterEntryTypes_UnknownKindErrors(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord": {"0.0.1"},
		"intoto": {"0.0.1", "0.0.2"},
	}

	_, err := filterEntryTypes(allEntries, []string{"rekord", "doesnotexist"})
	if err == nil {
		t.Fatal("expected error for unknown kind, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, `"doesnotexist"`) {
		t.Errorf("error should quote the bad kind, got: %v", err)
	}
	for _, want := range []string{"rekord", "intoto"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should list known kind %q, got: %v", want, err)
		}
	}
}

func TestFilterEntryTypes_KnownKindsListedSorted(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"zeta":  {"0.0.1"},
		"alpha": {"0.0.1"},
		"mu":    {"0.0.1"},
	}

	_, err := filterEntryTypes(allEntries, []string{"bogus"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	a, m, z := strings.Index(msg, "alpha"), strings.Index(msg, "mu"), strings.Index(msg, "zeta")
	if a == -1 || m == -1 || z == -1 {
		t.Fatalf("error message missing kinds: %s", msg)
	}
	if a >= m || m >= z {
		t.Errorf("expected sorted order alpha < mu < zeta in error, got: %s", msg)
	}
}

func TestFilterEntryTypes_DuplicatesAreIdempotent(t *testing.T) {
	t.Parallel()
	allEntries := map[string][]string{
		"rekord": {"0.0.1"},
		"intoto": {"0.0.1", "0.0.2"},
	}

	got, err := filterEntryTypes(allEntries, []string{"rekord", "rekord", "intoto"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"rekord", "intoto"}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("duplicate kinds should de-dupe\n got: %v\nwant: %v", got, want)
	}
}

func TestValidateScheme(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeTestCertKey(t)
	_, otherKeyPath := writeTestCertKey(t)

	tests := []struct {
		name      string
		scheme    string
		tlsCert   string
		tlsKey    string
		wantErr   bool
		errSubstr string
	}{
		{name: "default http only", scheme: "http"},
		{name: "https with cert and key", scheme: "https", tlsCert: certPath, tlsKey: keyPath},
		{
			name:      "unknown scheme rejected",
			scheme:    "htps",
			wantErr:   true,
			errSubstr: "unsupported scheme",
		},
		{
			name:      "https without cert",
			scheme:    "https",
			tlsKey:    keyPath,
			wantErr:   true,
			errSubstr: "requires both",
		},
		{
			name:      "https without key",
			scheme:    "https",
			tlsCert:   certPath,
			wantErr:   true,
			errSubstr: "requires both",
		},
		{
			name:      "https with missing cert file",
			scheme:    "https",
			tlsCert:   filepath.Join(t.TempDir(), "nope.pem"),
			tlsKey:    keyPath,
			wantErr:   true,
			errSubstr: "loading TLS certificate/key",
		},
		{
			name:      "https with mismatched cert and key",
			scheme:    "https",
			tlsCert:   certPath,
			tlsKey:    otherKeyPath,
			wantErr:   true,
			errSubstr: "loading TLS certificate/key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateScheme(tc.scheme, tc.tlsCert, tc.tlsKey)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q should contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// writeTestCertKey generates a self-signed ECDSA certificate/key pair, writes
// them as PEM files in a temp dir, and returns their paths.
func writeTestCertKey(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	return certPath, keyPath
}
