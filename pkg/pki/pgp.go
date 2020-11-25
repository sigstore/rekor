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

package pki

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"golang.org/x/crypto/openpgp"
)

// PGPSignature Signature that follows the PGP standard; supports both armored & binary detached signatures
type PGPSignature struct {
	isArmored bool
	signature []byte
}

// NewPGPSignature creates and validates a PGP signature object
func NewPGPSignature(r io.Reader) (*PGPSignature, error) {
	var s PGPSignature
	var inputBuffer bytes.Buffer

	if _, err := io.Copy(&inputBuffer, r); err != nil {
		return nil, fmt.Errorf("unable to read PGP signature: %w", err)
	}

	sigByteReader := bytes.NewReader(inputBuffer.Bytes())

	var sigReader io.Reader
	sigBlock, err := armor.Decode(sigByteReader)
	if err == nil {
		s.isArmored = true
		if sigBlock.Type != openpgp.SignatureType {
			return nil, fmt.Errorf("invalid PGP signature provided")
		}
		sigReader = sigBlock.Body
	} else {
		s.isArmored = false
		if _, err := sigByteReader.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("unable to read binary PGP signature: %w", err)
		}
		sigReader = sigByteReader
	}

	sigPktReader := packet.NewReader(sigReader)
	sigPkt, err := sigPktReader.Next()
	if err != nil {
		return nil, fmt.Errorf("invalid PGP signature: %w", err)
	}

	if _, ok := sigPkt.(*packet.Signature); !ok {
		if _, ok := sigPkt.(*packet.SignatureV3); !ok {
			return nil, fmt.Errorf("valid PGP signature was not detected")
		}
	}

	s.signature = inputBuffer.Bytes()
	return &s, nil
}

// FetchPGPSignature implements pki.Signature interface
func FetchPGPSignature(ctx context.Context, url string) (*PGPSignature, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error initializing fetch for PGP signature: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching PGP signature: %w", err)
	}
	defer resp.Body.Close()

	sig, err := NewPGPSignature(resp.Body)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// CanonicalValue implements the pki.Signature interface
func (s PGPSignature) CanonicalValue() ([]byte, error) {
	if len(s.signature) == 0 {
		return nil, fmt.Errorf("PGP signature has not been initialized")
	}

	if s.isArmored {
		return s.signature, nil
	}

	var canonicalBuffer bytes.Buffer
	// Use an inner function so we can defer the Close()
	if err := func() error {
		ew, err := armor.Encode(&canonicalBuffer, openpgp.SignatureType, nil)
		if err != nil {
			return fmt.Errorf("error encoding canonical value of PGP signature: %w", err)
		}
		defer ew.Close()

		if _, err := io.Copy(ew, bytes.NewReader(s.signature)); err != nil {
			return fmt.Errorf("error generating canonical value of PGP signature: %w", err)
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	return canonicalBuffer.Bytes(), nil
}

// Verify implements the pki.Signature interface
func (s PGPSignature) Verify(r io.Reader, k interface{}) error {
	if len(s.signature) == 0 {
		return fmt.Errorf("PGP signature has not been initialized")
	}

	key, ok := k.(*PGPPublicKey)
	if !ok {
		return fmt.Errorf("cannot use Verify with a non-PGP signature")
	}
	if len(key.key) == 0 {
		return fmt.Errorf("PGP public key has not been initialized")
	}

	verifyFn := openpgp.CheckDetachedSignature
	if s.isArmored {
		verifyFn = openpgp.CheckArmoredDetachedSignature
	}

	if _, err := verifyFn(key.key, r, bytes.NewReader(s.signature)); err != nil {
		return err
	}

	return nil
}

// PGPPublicKey Public Key that follows the PGP standard; supports both armored & binary detached signatures
type PGPPublicKey struct {
	key openpgp.EntityList
}

// NewPGPPublicKey implements the pki.PublicKey interface
func NewPGPPublicKey(r io.Reader) (*PGPPublicKey, error) {
	var k PGPPublicKey
	var inputBuffer bytes.Buffer

	startToken := []byte(`-----BEGIN PGP`)
	endToken := []byte(`-----END PGP`)

	bufferedReader := bufio.NewReader(r)
	armorCheck, err := bufferedReader.Peek(len(startToken))
	if err != nil {
		return nil, fmt.Errorf("unable to read PGP public key: %w", err)
	}
	if bytes.Equal(startToken, armorCheck) {
		// looks like we have armored input
		scan := bufio.NewScanner(bufferedReader)
		scan.Split(bufio.ScanLines)

		for scan.Scan() {
			line := scan.Bytes()
			inputBuffer.Write(line)
			fmt.Fprintf(&inputBuffer, "\n")

			if bytes.HasPrefix(line, endToken) {
				// we have a complete armored message; process it
				keyBlock, err := armor.Decode(&inputBuffer)
				if err == nil {
					if keyBlock.Type != openpgp.PublicKeyType && keyBlock.Type != openpgp.PrivateKeyType {
						return nil, fmt.Errorf("invalid PGP type detected")
					}
					keys, err := openpgp.ReadKeyRing(keyBlock.Body)
					if err != nil {
						return nil, fmt.Errorf("error reading PGP public key: %w", err)
					}
					if k.key == nil {
						k.key = keys
					} else {
						k.key = append(k.key, keys...)
					}
					inputBuffer.Reset()
				} else {
					return nil, fmt.Errorf("invalid PGP public key provided: %w", err)
				}
			}
		}
	} else {
		// process as binary
		k.key, err = openpgp.ReadKeyRing(bufferedReader)
		if err != nil {
			return nil, fmt.Errorf("error reading binary PGP public key: %w", err)
		}
	}

	if len(k.key) == len(k.key.DecryptionKeys()) {
		return nil, fmt.Errorf("no PGP public keys could be read")
	}

	return &k, nil
}

// FetchPGPPublicKey implements pki.PublicKey interface
func FetchPGPPublicKey(ctx context.Context, url string) (*PGPPublicKey, error) {
	//TODO: detect if url is hkp and adjust accordingly
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching PGP public key: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching PGP public key: %w", err)
	}
	defer resp.Body.Close()

	key, err := NewPGPPublicKey(resp.Body)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// CanonicalValue implements the pki.PublicKey interface
func (k PGPPublicKey) CanonicalValue() ([]byte, error) {
	if k.key == nil {
		return nil, fmt.Errorf("PGP public key has not been initialized")
	}

	var canonicalBuffer bytes.Buffer

	// Use an inner function so we can defer the close()
	if err := func() error {
		armoredWriter, err := armor.Encode(&canonicalBuffer, openpgp.PublicKeyType, nil)
		if err != nil {
			return fmt.Errorf("error generating canonical value of PGP public key: %w", err)
		}
		defer armoredWriter.Close()

		for _, entity := range k.key {
			if err := entity.Serialize(armoredWriter); err != nil {
				return fmt.Errorf("error generating canonical value of PGP public key: %w", err)
			}
		}
		return nil
	}(); err != nil {
		return nil, err
	}

	return canonicalBuffer.Bytes(), nil
}
