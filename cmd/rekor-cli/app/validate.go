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

package app

import (
	"errors"
	"fmt"
	"strings"

	validator "github.com/asaskevich/govalidator"
)

// validateSHA512Value ensures that the supplied string matches the
// following format: [sha512:]<128 hexadecimal characters>
// where [sha512:] is optional
func validateSHA512Value(v string) error {
	var prefix, hash string

	split := strings.SplitN(v, ":", 2)
	switch len(split) {
	case 1:
		hash = split[0]
	case 2:
		prefix = split[0]
		hash = split[1]
	}

	if strings.TrimSpace(prefix) != "" && prefix != "sha512" {
		return fmt.Errorf("invalid prefix '%v'", prefix)
	}

	if !validator.IsSHA512(strings.ToLower(hash)) {
		return errors.New("invalid SHA512 value")
	}
	return nil
}

// validateSHA256Value ensures that the supplied string matches the following format:
// [sha256:]<64 hexadecimal characters>
// where [sha256:] is optional
func validateSHA256Value(v string) error {
	var prefix, hash string

	split := strings.SplitN(v, ":", 2)
	switch len(split) {
	case 1:
		hash = split[0]
	case 2:
		prefix = split[0]
		hash = split[1]
	}

	if strings.TrimSpace(prefix) != "" && prefix != "sha256" {
		return fmt.Errorf("invalid prefix '%v'", prefix)
	}

	if !validator.IsSHA256(strings.ToLower(hash)) {
		return errors.New("invalid SHA256 value")
	}
	return nil
}

func validateSHA1Value(v string) error {
	var prefix, hash string

	split := strings.SplitN(v, ":", 2)
	switch len(split) {
	case 1:
		hash = split[0]
	case 2:
		prefix = split[0]
		hash = split[1]
	}

	if strings.TrimSpace(prefix) != "" && prefix != "sha1" {
		return fmt.Errorf("invalid prefix '%v'", prefix)
	}

	if !validator.IsSHA1(strings.ToLower(hash)) {
		return errors.New("invalid SHA1 value")
	}
	return nil
}
