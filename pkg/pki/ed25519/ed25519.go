/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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

package ed25519

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	minisign "github.com/jedisct1/go-minisign"
)

// Signature Signature that follows the ed25519 standard; supports both minisign and signify generated signatures
type Signature struct {
	signature *minisign.Signature
}

// NewSignature creates and validates a ed25519 signature object
func NewSignature(r io.Reader) (*Signature, error) {
	var s Signature
	var inputBuffer bytes.Buffer

	if _, err := io.Copy(&inputBuffer, r); err != nil {
		return nil, fmt.Errorf("unable to read ed25519 signature: %w", err)
	}

	inputString := string(inputBuffer.Bytes())
	signature, err := minisign.DecodeSignature(inputString)
	if err != nil {
		//try to parse as signify
		lines := strings.Split(strings.TrimRight(inputString, "\n"), "\n")
		if len(lines) != 2 {
			return nil, fmt.Errorf("invalid signature provided: %v lines detected", len(lines))
		}
		sigBytes, b64Err := base64.StdEncoding.DecodeString(lines[1])
		if b64Err != nil {
			return nil, fmt.Errorf("invalid signature provided: base64 decoding failed")
		}
		if len(sigBytes) != ed25519.SignatureSize+10 {
			return nil, fmt.Errorf("invalid signature provided: incorrect size %v detected", len(sigBytes))
		}
		copy(signature.Signature[:], sigBytes[10:])
	}
	s.signature = &signature
	return &s, nil
}

// FetchSignature implements pki.Signature interface
func FetchSignature(ctx context.Context, url string) (*Signature, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing fetch for ed25519 signature: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching ed25519 signature: %w", err)
	}
	defer resp.Body.Close()

	sig, err := NewSignature(resp.Body)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// CanonicalValue implements the pki.Signature interface
func (s Signature) CanonicalValue() ([]byte, error) {
	if s.signature == nil {
		return nil, fmt.Errorf("ed25519 signature has not been initialized")
	}

	buf := bytes.NewBuffer([]byte("untrusted comment:\n"))
	b64Buf := bytes.NewBuffer(s.signature.SignatureAlgorithm[:])
	if _, err := b64Buf.Write(s.signature.KeyId[:]); err != nil {
		return nil, fmt.Errorf("error canonicalizing ed25519 signature: %w", err)
	}
	if _, err := b64Buf.Write(s.signature.Signature[:]); err != nil {
		return nil, fmt.Errorf("error canonicalizing ed25519 signature: %w", err)
	}
	if _, err := buf.WriteString(base64.StdEncoding.EncodeToString(b64Buf.Bytes())); err != nil {
		return nil, fmt.Errorf("error canonicalizing ed25519 signature: %w", err)
	}
	return buf.Bytes(), nil
}

// Verify implements the pki.Signature interface
func (s Signature) Verify(r io.Reader, k interface{}) error {
	if s.signature == nil {
		return fmt.Errorf("ed25519 signature has not been initialized")
	}

	key, ok := k.(*PublicKey)
	if !ok {
		return fmt.Errorf("cannot use Verify with a non-ed25519 key")
	}
	if key.key == nil {
		return fmt.Errorf("ed25519 public key has not been initialized")
	}

	msg, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("error reading message to verify signature: %w", err)
	}

	if ok := ed25519.Verify(ed25519.PublicKey(key.key.PublicKey[:]), msg, s.signature.Signature[:]); !ok {
		return fmt.Errorf("verification of signed message failed")
	}

	return nil
}

// PublicKey Public Key that follows the ed25519 standard; supports signify and minisign public keys
type PublicKey struct {
	key *minisign.PublicKey
}

// NewPublicKey implements the pki.PublicKey interface
func NewPublicKey(r io.Reader) (*PublicKey, error) {
	var k PublicKey
	var inputBuffer bytes.Buffer

	if _, err := io.Copy(&inputBuffer, r); err != nil {
		return nil, fmt.Errorf("unable to read ed25519 public key: %w", err)
	}

	inputString := string(inputBuffer.Bytes())
	key, err := minisign.DecodePublicKey(inputString)
	if err != nil {
		//try as a standalone base64 string
		key, err = minisign.NewPublicKey(inputString)
		if err != nil {
			return nil, fmt.Errorf("unable to read ed25519 public key: %w", err)
		}
	}
	k.key = &key
	return &k, nil
}

// FetchPublicKey implements pki.PublicKey interface
func FetchPublicKey(ctx context.Context, url string) (*PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching ed25519 public key: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching ed25519 public key: %w", err)
	}
	defer resp.Body.Close()

	key, err := NewPublicKey(resp.Body)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// CanonicalValue implements the pki.PublicKey interface
func (k PublicKey) CanonicalValue() ([]byte, error) {
	if k.key == nil {
		return nil, fmt.Errorf("ed25519 public key has not been initialized")
	}

	return k.key.PublicKey[:], nil
}
