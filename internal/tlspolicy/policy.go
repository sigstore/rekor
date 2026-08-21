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

// Package tlspolicy holds the TLS policy for the Rekor API listener and applies
// it to the server's TLS config.
package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Policy is a TLS policy for the API listener.
type Policy struct {
	MinVersion   uint16
	CipherSuites []uint16
}

// current holds the active policy. It is set once at startup, before the server
// starts serving, so no synchronization is required.
var current Policy

// Set stores the policy applied by Apply.
func Set(p Policy) {
	current = p
}

// Apply updates cfg from the stored policy, leaving unset fields unchanged.
func Apply(cfg *tls.Config) {
	p := current

	if p.MinVersion != 0 {
		cfg.MinVersion = p.MinVersion
	}
	if len(p.CipherSuites) > 0 {
		cfg.CipherSuites = p.CipherSuites
	}
}

// Parse builds a Policy from raw flag values.
func Parse(minVersion string, cipherSuites []string) (Policy, error) {
	mv, err := parseMinVersion(minVersion)
	if err != nil {
		return Policy{}, err
	}
	cs, err := parseCipherSuites(cipherSuites)
	if err != nil {
		return Policy{}, err
	}
	return Policy{MinVersion: mv, CipherSuites: cs}, nil
}

// parseMinVersion maps "1.2"/"1.3" to their crypto/tls constants. A blank value
// is treated as unset and defaults to TLS 1.3, matching the flag default.
func parseMinVersion(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "", "1.3":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported TLS minimum version %q: supported values are 1.2 and 1.3", v)
	}
}

// tls12CipherSuites returns the secure, configurable cipher suites that apply to
// TLS 1.2, as an id-by-name map and a sorted list of their names. TLS 1.3 suites
// are fixed by Go and are excluded.
func tls12CipherSuites() (map[string]uint16, []string) {
	byName := make(map[string]uint16)
	names := make([]string, 0)
	for _, c := range tls.CipherSuites() {
		if !slices.Contains(c.SupportedVersions, tls.VersionTLS12) {
			continue
		}
		byName[c.Name] = c.ID
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return byName, names
}

// CipherSuiteNames returns the sorted names of the secure cipher suites that can
// be configured for TLS 1.2. TLS 1.3 suites are fixed by Go and excluded.
func CipherSuiteNames() []string {
	_, names := tls12CipherSuites()
	return names
}

// parseCipherSuites maps cipher suite names to their IDs, accepting only the
// secure suites that apply to TLS 1.2. TLS 1.3 suites are fixed by Go and are
// rejected here.
func parseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}

	secure, secureNames := tls12CipherSuites()

	ids := make([]uint16, 0, len(names))
	for _, raw := range names {
		// Split on commas so a single comma-separated element works too. pflag
		// splits StringSlice flags on commas, but a value sourced from an env var
		// (e.g. TLS_CIPHER_SUITES="A,B") arrives as one element; normalize both.
		for _, field := range strings.Split(raw, ",") {
			name := strings.TrimSpace(field)
			if name == "" {
				continue
			}
			id, ok := secure[name]
			if !ok {
				return nil, fmt.Errorf("unknown TLS 1.2 cipher suite %q: valid values are %s", name, strings.Join(secureNames, ", "))
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}
