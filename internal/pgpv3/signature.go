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

// Package pgpv3 provides Rekor's integration with legacy v3 signatures.
// Unmodified upstream files live in upstream; modified code lives in adapted.
package pgpv3

import (
	"encoding"
	"io"
	"strconv"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/sigstore/rekor/internal/pgpv3/adapted"
)

// Signature adds detached verification to the adapted upstream signature.
type Signature struct {
	adapted.Signature
}

// Parse reads an unframed v2 or v3 signature packet body.
func Parse(contents []byte) (*Signature, error) {
	sig, err := adapted.Parse(contents)
	if err != nil {
		return nil, err
	}
	return &Signature{Signature: *sig}, nil
}

// IsV3Packet reports whether an opaque packet contains a v2 or v3 signature.
func IsV3Packet(tag uint8, contents []byte) bool {
	return tag == 2 && len(contents) > 0 && contents[0] >= 2 && contents[0] <= 3
}

// VerifyDetached verifies sig against signed using the candidate keys.
//
// Key revocation and expiration are deliberately not evaluated here. This
// matches the previous OpenPGP verifier's v3 path and is required when
// replaying historical transparency-log entries.
func (sig *Signature) VerifyDetached(keys []openpgp.Key, signed io.Reader) (*openpgp.Entity, error) {
	if len(keys) == 0 {
		return nil, errors.ErrUnknownIssuer
	}

	h, err := sig.PrepareVerify()
	if err != nil {
		return nil, err
	}

	var wrapped io.Writer
	switch sig.SigType {
	case packet.SigTypeBinary:
		wrapped = h
	case packet.SigTypeText:
		wrapped = openpgp.NewCanonicalTextHash(h)
	default:
		return nil, errors.UnsupportedError("unsupported signature type: " + strconv.Itoa(int(sig.SigType)))
	}

	if _, err := io.Copy(wrapped, signed); err != nil {
		return nil, err
	}

	// Verify writes a trailer into h, so the digest state has to be restored
	// between candidate keys.
	var state []byte
	if len(keys) > 1 {
		m, ok := h.(encoding.BinaryMarshaler)
		if !ok {
			return nil, errors.UnsupportedError("hash state cannot be saved")
		}
		state, err = m.MarshalBinary()
		if err != nil {
			return nil, err
		}
	}
	for i, key := range keys {
		if i > 0 {
			u, ok := h.(encoding.BinaryUnmarshaler)
			if !ok || state == nil {
				break
			}
			if err := u.UnmarshalBinary(state); err != nil {
				break
			}
		}
		if err = sig.Verify(h, key.PublicKey); err == nil {
			return key.Entity, nil
		}
	}
	return nil, err
}
