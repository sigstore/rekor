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

package pgpv3

import (
	"bytes"
	"errors"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrNotV3 indicates that a packet requires the upstream parser.
var ErrNotV3 = errors.New("not a v3 signature packet")

// ParseStrict reads exactly one framed v3 signature, as required by RPM tags.
// Parse instead accepts an unframed packet body.
func ParseStrict(encoded []byte) (*Signature, error) {
	r := bytes.NewReader(encoded)
	op, err := packet.NewOpaqueReader(r).Next()
	if err != nil {
		return nil, err
	}
	if !IsV3Packet(op.Tag, op.Contents) {
		return nil, ErrNotV3
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing data after v3 signature packet")
	}
	return Parse(op.Contents)
}
