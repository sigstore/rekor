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

package hashedrekord

import (
	"context"
	"net/url"
	"testing"

	"github.com/sigstore/rekor/pkg/types"
)

func FuzzHashedRekord(f *testing.F) {
	f.Fuzz(func(t *testing.T, version, artifact, pkiFormat, scheme, host, path string, signature, authentication []byte) {
		ctx := context.Background()
		hrd := New()
		u := url.URL{Scheme: scheme, Host: host, Path: path}

		props := types.ArtifactProperties{ArtifactHash: artifact, PKIFormat: pkiFormat,
			SignatureBytes: signature, AdditionalAuthenticatedData: authentication, ArtifactPath: &u,
			SignaturePath: &u, PublicKeyPaths: []*url.URL{&u}}
		entry, err := hrd.CreateProposedEntry(ctx, version, props)
		if err != nil {
			t.Skip("skipping fuzz test due to error: ", err)
		}
		_, err = hrd.UnmarshalEntry(entry)
		if err != nil {
			t.Skip("skipping fuzz test due to unmarshal error: ", err)
		}
	})
}
