/*
Copyright The Rekor Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"context"
	"crypto"
	"strings"

	"github.com/sigstore/cosign/pkg/cosign/kms/gcp"
)

type gcpkms struct {
	*gcp.KMS
}

func newGCPKMS(ctx context.Context, signer string) (*gcpkms, error) {
	keyResourceID := strings.TrimPrefix(signer, gcp.ReferenceScheme)
	kms, err := gcp.NewGCP(ctx, keyResourceID)
	return &gcpkms{kms}, err
}

func (g *gcpkms) Sign(ctx context.Context, payload []byte) (signature []byte, err error) {
	return g.KMS.Sign(ctx, payload)
}

func (g *gcpkms) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return g.KMS.PublicKey(ctx)
}
