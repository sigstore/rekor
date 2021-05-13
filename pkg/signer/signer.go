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
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore/pkg/kms/gcp"
	"github.com/sigstore/sigstore/pkg/signature"
)

func New(ctx context.Context, signer string) (signature.Signer, []*x509.Certificate, error) {
	switch {
	case strings.HasPrefix(signer, gcp.ReferenceScheme):
		kms, err := gcp.NewGCP(ctx, signer)
		// TODO: Get a timestamping cert issued by a Root CA.
		return kms, nil, err
	case signer == MemoryScheme:
		mem, err := NewMemory()
		if err != nil {
			return nil, nil, err
		}
		return mem.Signer, mem.CertChain, err
	default:
		return nil, nil, fmt.Errorf("please provide a valid signer, %v is not valid", signer)
	}
}
