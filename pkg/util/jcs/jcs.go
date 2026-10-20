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

// Package jcs implements the JSON Canonicalization Scheme (RFC 8785) on top of
// the standard library's encoding/json/jsontext package.
package jcs

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// maxFloatToken is how jsontext formats ±math.MaxFloat64. It is also what
// jsontext silently substitutes for a number outside the float64 range, so
// its presence in the output means the input needs a closer look.
var maxFloatToken = []byte("1.7976931348623157e+308")

// Canonicalize returns the RFC 8785 canonical form of the JSON value in b.
// b is not modified.
//
// Numbers outside the float64 range are rejected rather than clamped to
// ±math.MaxFloat64, so that canonicalization never changes the value of the
// input.
func Canonicalize(b []byte) ([]byte, error) {
	// Canonicalize works in place; copy so callers' buffers are left alone.
	v := jsontext.Value(bytes.Clone(b))
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	if bytes.Contains(v, maxFloatToken) {
		if err := checkNumberRange(b); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// checkNumberRange returns an error if any number in b overflows a float64.
func checkNumberRange(b []byte) error {
	dec := jsontext.NewDecoder(bytes.NewReader(b))
	for {
		tok, err := dec.ReadToken()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if tok.Kind() != '0' {
			continue
		}
		if _, err := tok.Float(); errors.Is(err, strconv.ErrRange) {
			return fmt.Errorf("jcs: number %s is out of float64 range", tok.String())
		}
	}
}
