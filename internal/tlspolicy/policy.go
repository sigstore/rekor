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

// Package tlspolicy holds the operator-configured TLS policy for the Rekor API
// listener and applies it from the generated server's configureTLS hook.
package tlspolicy

import (
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Policy is a parsed, validated TLS policy for the API listener.
type Policy struct {
	MinVersion   uint16
	CipherSuites []uint16
}

var (
	mu      sync.RWMutex
	current Policy
)

// Set stores the policy to be applied by Apply.
func Set(p Policy) {
	mu.Lock()
	defer mu.Unlock()
	current = p
}

// Apply mutates cfg according to the stored policy. Unset fields are left as-is.
func Apply(cfg *tls.Config) {
	mu.RLock()
	p := current
	mu.RUnlock()

	if p.MinVersion != 0 {
		cfg.MinVersion = p.MinVersion
	}
	if len(p.CipherSuites) > 0 {
		cfg.CipherSuites = p.CipherSuites
	}
}

// Parse builds a Policy from raw flag values, rejecting unsupported versions and
// unknown or insecure cipher suite names.
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

// parseMinVersion maps "1.2"/"1.3" to their crypto/tls constants, defaulting to
// TLS 1.3 when unset.
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

// parseCipherSuites maps crypto/tls cipher suite names to their IDs, accepting
// only the secure suites and rejecting insecure or unknown names. Applies to
// TLS 1.2 only; Go fixes the TLS 1.3 suite set.
func parseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}

	secure := make(map[string]uint16)
	for _, c := range tls.CipherSuites() {
		secure[c.Name] = c.ID
	}
	insecure := make(map[string]struct{})
	for _, c := range tls.InsecureCipherSuites() {
		insecure[c.Name] = struct{}{}
	}

	ids := make([]uint16, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		id, ok := secure[name]
		if !ok {
			if _, bad := insecure[name]; bad {
				return nil, fmt.Errorf("insecure TLS cipher suite %q is not permitted", name)
			}
			return nil, fmt.Errorf("unknown TLS cipher suite %q: valid values are %s", name, strings.Join(secureCipherSuiteNames(), ", "))
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func secureCipherSuiteNames() []string {
	names := make([]string, 0)
	for _, c := range tls.CipherSuites() {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	return names
}
