//
// Copyright 2021 The Sigstore Authors.
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

package util

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/pubkey"
)

func PublicKey(ctx context.Context, c *client.Rekor) (*ecdsa.PublicKey, error) {
	resp, err := c.Pubkey.GetPublicKey(&pubkey.GetPublicKeyParams{Context: ctx})
	if err != nil {
		return nil, err
	}
	pubKey := resp.GetPayload()

	// marshal the pubkey
	p, _ := pem.Decode([]byte(pubKey))
	if p == nil {
		return nil, errors.New("public key shouldn't be nil")
	}

	decoded, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := decoded.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}
	return ed, nil
}
