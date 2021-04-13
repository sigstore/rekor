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

	"github.com/smallstep/certificates/cas/apiv1"
)

// Smallstep covers a variety of KMS providers, including GCP and Amazon
// A list can be found here: https://github.com/smallstep/certificates/tree/master/kms
type Smallstep struct {
	opts apiv1.Options
}

func NewSmallstep(opts apiv1.Options) *Smallstep {
	return &Smallstep{opts}
}

func (s *Smallstep) Sign(ctx context.Context, payload []byte) (signature []byte, err error) {

	return nil, nil
}

func (s *Smallstep) PublicKey(ctx context.Context) (crypto.PublicKey, error) {

	return nil, nil
}
