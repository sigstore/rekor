// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package x509

import (
	"net"
	"net/url"
	"testing"

	"github.com/sigstore/rekor/pkg/pki/x509/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestGetSubjectAltnernativeNames(t *testing.T) {
	rootCert, rootKey, _ := testutils.GenerateRootCa()
	subCert, subKey, _ := testutils.GenerateSubordinateCa(rootCert, rootKey)

	// generate with OtherName, which will override other SANs
	ext, err := cryptoutils.MarshalOtherNameSAN("subject-othername", true)
	if err != nil {
		t.Fatalf("error marshalling SANs: %v", err)
	}
	leafCert, _, _ := testutils.GenerateLeafCert("unused", "oidc-issuer", nil, subCert, subKey, *ext)

	sans := GetSubjectAlternateNames(leafCert)
	if len(sans) != 1 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-othername" {
		t.Fatalf("unexpected OtherName SAN value")
	}

	// generate with all other SANs
	leafCert, _, _ = testutils.GenerateLeafCertWithSubjectAlternateNames([]string{"subject-dns"}, []string{"subject-email"}, []net.IP{{1, 2, 3, 4}}, []*url.URL{{Path: "testURL"}}, "oidc-issuer", subCert, subKey)
	sans = GetSubjectAlternateNames(leafCert)
	if len(sans) != 4 {
		t.Fatalf("expected 1 SAN field, got %d", len(sans))
	}
	if sans[0] != "subject-dns" {
		t.Fatalf("unexpected DNS SAN value")
	}
	if sans[1] != "subject-email" {
		t.Fatalf("unexpected email SAN value")
	}
	if sans[2] != "1.2.3.4" {
		t.Fatalf("unexpected IP SAN value")
	}
	if sans[3] != "testURL" {
		t.Fatalf("unexpected URL SAN value")
	}
}
