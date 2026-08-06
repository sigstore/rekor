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

package tlspolicy

import (
	"crypto/tls"
	"testing"
)

func TestParseMinVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint16
		wantErr bool
	}{
		{name: "empty defaults to 1.3", input: "", want: tls.VersionTLS13},
		{name: "whitespace defaults to 1.3", input: "  ", want: tls.VersionTLS13},
		{name: "1.2", input: "1.2", want: tls.VersionTLS12},
		{name: "1.3", input: "1.3", want: tls.VersionTLS13},
		{name: "trimmed 1.3", input: " 1.3 ", want: tls.VersionTLS13},
		{name: "unsupported 1.1", input: "1.1", wantErr: true},
		{name: "garbage", input: "tls1.3", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMinVersion(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func firstTLS12Suite(t *testing.T) *tls.CipherSuite {
	t.Helper()
	for _, c := range tls.CipherSuites() {
		for _, v := range c.SupportedVersions {
			if v == tls.VersionTLS12 {
				return c
			}
		}
	}
	t.Fatal("no TLS 1.2 cipher suite found")
	return nil
}

func firstTLS13OnlySuite(t *testing.T) string {
	t.Helper()
	for _, c := range tls.CipherSuites() {
		if len(c.SupportedVersions) == 1 && c.SupportedVersions[0] == tls.VersionTLS13 {
			return c.Name
		}
	}
	t.Fatal("no TLS 1.3-only cipher suite found")
	return ""
}

func TestParseCipherSuites(t *testing.T) {
	suite := firstTLS12Suite(t)
	valid := suite.Name
	validID := suite.ID

	t.Run("empty leaves default", func(t *testing.T) {
		got, err := parseCipherSuites(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("valid name resolves to id", func(t *testing.T) {
		got, err := parseCipherSuites([]string{valid})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != validID {
			t.Fatalf("got %v, want [%d]", got, validID)
		}
	})

	t.Run("blank entries skipped", func(t *testing.T) {
		got, err := parseCipherSuites([]string{"", valid, "  "})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != validID {
			t.Fatalf("got %v, want [%d]", got, validID)
		}
	})

	t.Run("comma-separated single element split", func(t *testing.T) {
		// An env-sourced value (e.g. TLS_CIPHER_SUITES="A,B") arrives as one
		// element; it must split the same way pflag splits a StringSlice flag.
		got, err := parseCipherSuites([]string{valid + "," + valid})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0] != validID || got[1] != validID {
			t.Fatalf("got %v, want [%d %d]", got, validID, validID)
		}
	})

	t.Run("unknown name rejected", func(t *testing.T) {
		if _, err := parseCipherSuites([]string{"NOT_A_SUITE"}); err == nil {
			t.Fatal("expected error for unknown suite")
		}
	})

	t.Run("insecure name rejected", func(t *testing.T) {
		insecure := tls.InsecureCipherSuites()[0].Name
		if _, err := parseCipherSuites([]string{insecure}); err == nil {
			t.Fatalf("expected error for insecure suite %q", insecure)
		}
	})

	t.Run("tls 1.3-only name rejected", func(t *testing.T) {
		only13 := firstTLS13OnlySuite(t)
		if _, err := parseCipherSuites([]string{only13}); err == nil {
			t.Fatalf("expected error for TLS 1.3-only suite %q", only13)
		}
	})
}

func TestParse(t *testing.T) {
	valid := firstTLS12Suite(t).Name

	p, err := Parse("1.3", []string{valid})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.MinVersion != tls.VersionTLS13 {
		t.Fatalf("got min version %d, want %d", p.MinVersion, tls.VersionTLS13)
	}
	if len(p.CipherSuites) != 1 {
		t.Fatalf("got %d cipher suites, want 1", len(p.CipherSuites))
	}

	if _, err := Parse("1.1", nil); err == nil {
		t.Fatal("expected error for unsupported version")
	}
	if _, err := Parse("", []string{"bogus"}); err == nil {
		t.Fatal("expected error for unknown cipher suite")
	}
}

func TestApply(t *testing.T) {
	t.Cleanup(func() { Set(Policy{}) })

	t.Run("unset policy leaves config untouched", func(t *testing.T) {
		Set(Policy{})
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: []uint16{42}}
		Apply(cfg)
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Fatalf("min version changed to %d", cfg.MinVersion)
		}
		if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != 42 {
			t.Fatalf("cipher suites changed to %v", cfg.CipherSuites)
		}
	})

	t.Run("set policy overrides config", func(t *testing.T) {
		Set(Policy{MinVersion: tls.VersionTLS13, CipherSuites: []uint16{99}})
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		Apply(cfg)
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Fatalf("got min version %d, want %d", cfg.MinVersion, tls.VersionTLS13)
		}
		if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != 99 {
			t.Fatalf("got cipher suites %v, want [99]", cfg.CipherSuites)
		}
	})
}
