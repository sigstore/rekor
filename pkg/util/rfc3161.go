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
	"crypto"
	"encoding/asn1"
	"fmt"

	"github.com/sassoftware/relic/lib/pkcs9"
	"github.com/sassoftware/relic/lib/x509tools"
)

func TimestampRequestFromData(data []byte) (*pkcs9.TimeStampReq, error) {
	// Use a default hash algorithm right now
	hash := crypto.SHA256
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	digest := h.Sum(nil)
	alg, _ := x509tools.PkixDigestAlgorithm(hash)
	msg := pkcs9.TimeStampReq{
		Version: 1,
		MessageImprint: pkcs9.MessageImprint{
			HashAlgorithm: alg,
			HashedMessage: digest,
		},
		Nonce:   x509tools.MakeSerial(),
		CertReq: true,
	}
	return &msg, nil
}

func ParseTimestampRequest(data []byte) (*pkcs9.TimeStampReq, error) {
	msg := new(pkcs9.TimeStampReq)
	if rest, err := asn1.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("error umarshalling request")
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("error umarshalling request, trailing bytes")
	}
	return msg, nil
}
