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

package sign

import (
	"context"
	"crypto"
	"fmt"

	"github.com/smallstep/certificates/cas/apiv1"
)

type Signer interface {
	// Sign is responsible for signing the payload and returning a signature
	Sign(ctx context.Context, payload []byte) (signature []byte, err error)
	// PublicKey returns the public key for the signer
	PublicKey(ctx context.Context) (crypto.PublicKey, error)
}

func New(opts apiv1.Options) (Signer, error) {
	if ss := NewSmallstep(opts); ss != nil {
		return ss, nil
	}
	return nil, fmt.Errorf("please specify a valid signer")
}
