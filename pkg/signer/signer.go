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
	"fmt"
	"strings"

	"github.com/sigstore/cosign/pkg/cosign/kms/gcp"
)

type Signer interface {
	// Sign is responsible for signing the payload and returning a signature
	Sign(ctx context.Context, payload []byte) (signature []byte, signed []byte, err error)
	// PublicKey returns the public key for the signer
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
}

func New(ctx context.Context, signer string) (Signer, error) {
	switch {
	case strings.HasPrefix(signer, gcp.ReferenceScheme):
		return newGCPKMS(ctx, signer)
	default:
		return nil, fmt.Errorf("please provide a valid signer")
	}
}
