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
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/mod/sumdb/note"
)

// heavily borrowed from https://github.com/google/trillian-examples/blob/master/formats/log/checkpoint.go

type Checkpoint struct {
	// Ecosystem is the ecosystem/version string
	Ecosystem string
	// Size is the number of entries in the log at this checkpoint.
	Size uint64
	// Hash is the hash which commits to the contents of the entire log.
	Hash []byte
	// OtherContent is any additional data to be included in the signed payload; each element is assumed to be one line
	OtherContent []string
}

// String returns the String representation of the Checkpoint
func (c Checkpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Ecosystem, c.Size, base64.StdEncoding.EncodeToString(c.Hash))
	for _, line := range c.OtherContent {
		fmt.Fprintf(&b, "%s\n", line)
	}
	return b.String()
}

// MarshalText returns the common format representation of this Checkpoint.
func (c Checkpoint) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// UnmarshalText parses the common formatted checkpoint data and stores the result
// in the Checkpoint.
//
// The supplied data is expected to begin with the following 3 lines of text,
// each followed by a newline:
// <ecosystem/version string>
// <decimal representation of log size>
// <base64 representation of root hash>
// <optional non-empty line of other content>...
// <optional non-empty line of other content>...
//
// This will discard any content found after the checkpoint (including signatures)
func (c *Checkpoint) UnmarshalText(data []byte) error {
	l := bytes.Split(data, []byte("\n"))
	if len(l) < 4 {
		return errors.New("invalid checkpoint - too few newlines")
	}
	eco := string(l[0])
	if len(eco) == 0 {
		return errors.New("invalid checkpoint - empty ecosystem")
	}
	size, err := strconv.ParseUint(string(l[1]), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid checkpoint - size invalid: %w", err)
	}
	h, err := base64.StdEncoding.DecodeString(string(l[2]))
	if err != nil {
		return fmt.Errorf("invalid checkpoint - invalid hash: %w", err)
	}
	*c = Checkpoint{
		Ecosystem: eco,
		Size:      size,
		Hash:      h,
	}
	if len(l) >= 5 {
		for _, line := range l[3:] {
			if len(line) == 0 {
				break
			}
			c.OtherContent = append(c.OtherContent, string(line))
		}
	}
	return nil
}

func (c Checkpoint) Sign(identity string, signer crypto.Signer, opts crypto.SignerOpts) (*note.Signature, error) {
	hf := crypto.SHA256
	if opts != nil {
		hf = opts.HashFunc()
	}

	input, _ := c.MarshalText()
	var digest []byte
	if hf != crypto.Hash(0) {
		hasher := hf.New()
		_, err := hasher.Write(input)
		if err != nil {
			return nil, errors.Wrap(err, "hashing checkpoint before signing")
		}
		digest = hasher.Sum(nil)
	} else {
		digest, _ = c.MarshalText()
	}

	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, errors.Wrap(err, "signing checkpoint")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, errors.Wrap(err, "marshalling public key")
	}

	pkSha := sha256.Sum256(pubKeyBytes)

	signature := note.Signature{
		Name:   identity,
		Hash:   binary.BigEndian.Uint32(pkSha[:]),
		Base64: base64.StdEncoding.EncodeToString(sig),
	}

	return &signature, nil

}

type SignedCheckpoint struct {
	Checkpoint
	// Signatures are one or more signature lines covering the payload
	Signatures []note.Signature
}

// String returns the String representation of the SignedCheckpoint
func (s SignedCheckpoint) String() string {
	var b strings.Builder
	b.WriteString(s.Checkpoint.String())
	b.WriteRune('\n')
	for _, sig := range s.Signatures {
		var hbuf [4]byte
		binary.BigEndian.PutUint32(hbuf[:], sig.Hash)
		sigBytes, _ := base64.StdEncoding.DecodeString(sig.Base64)
		b64 := base64.StdEncoding.EncodeToString(append(hbuf[:], sigBytes...))
		fmt.Fprintf(&b, "%c %s %s\n", '\u2014', sig.Name, b64)
	}

	return b.String()
}

// UnmarshalText parses the common formatted checkpoint data and stores the result
// in the SignedCheckpoint. THIS DOES NOT VERIFY SIGNATURES INSIDE THE CONTENT!
//
// The supplied data is expected to contain a single Checkpoint, followed by a single
// line with no comment, followed by one or more lines with the following format:
//
// \u2014 name signature
//
// * name is the string associated with the signer
// * signature is a base64 encoded string; the first 4 bytes of the decoded value is a
//   hint to the public key; it is a big-endian encoded uint32 representing the first
//   4 bytes of the SHA256 hash of the public key
func (s *SignedCheckpoint) UnmarshalText(data []byte) error {
	sc := SignedCheckpoint{}

	if err := sc.Checkpoint.UnmarshalText(data); err != nil {
		return errors.Wrap(err, "parsing checkpoint portion")
	}

	b := bufio.NewScanner(bytes.NewReader(data))
	var pastCheckpoint bool
	for b.Scan() {
		if len(b.Text()) == 0 {
			pastCheckpoint = true
			continue
		}
		if pastCheckpoint {
			var name, signature string
			if _, err := fmt.Fscanf(strings.NewReader(b.Text()), "\u2014 %s %s\n", &name, &signature); err != nil {
				return errors.Wrap(err, "parsing signature")
			}

			sigBytes, err := base64.StdEncoding.DecodeString(signature)
			if err != nil {
				return errors.Wrap(err, "decoding signature")
			}
			if len(sigBytes) < 5 {
				return errors.New("signature is too small")
			}

			sig := note.Signature{
				Name:   name,
				Hash:   binary.BigEndian.Uint32(sigBytes[0:4]),
				Base64: base64.StdEncoding.EncodeToString(sigBytes[4:]),
			}
			sc.Signatures = append(sc.Signatures, sig)
		}
	}
	if len(sc.Signatures) == 0 {
		return errors.New("no signatures found in input")
	}

	// copy sc to s
	*s = sc
	return nil
}

// Verify checks that one of the signatures can be successfully verified using
// the supplied public key
func (s SignedCheckpoint) Verify(public crypto.PublicKey) bool {
	if len(s.Signatures) == 0 {
		return false
	}

	msg, _ := s.Checkpoint.MarshalText()
	//TODO: generalize this
	digest := sha256.Sum256(msg)

	for _, s := range s.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(s.Base64)
		if err != nil {
			return false
		}
		switch pk := public.(type) {
		case *rsa.PublicKey:
			if err := rsa.VerifyPSS(pk, crypto.SHA256, digest[:], sigBytes, &rsa.PSSOptions{Hash: crypto.SHA256}); err == nil {
				return true
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pk, digest[:], sigBytes) {
				return true
			}
		case *ed25519.PublicKey:
			if ed25519.Verify(*pk, msg, sigBytes) {
				return true
			}
		default:
			return false
		}
	}
	return false
}

// Sign adds an additional signature to a SignedCheckpoint object
// The signature is added to the signature array as well as being directly returned to the caller
func (s *SignedCheckpoint) Sign(identity string, signer crypto.Signer, opts crypto.SignerOpts) (*note.Signature, error) {
	sig, err := s.Checkpoint.Sign(identity, signer, opts)
	if err != nil {
		return nil, err
	}
	s.Signatures = append(s.Signatures, *sig)
	return sig, nil
}

// MarshalText returns the common format representation of this SignedCheckpoint.
func (s SignedCheckpoint) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

func SignedCheckpointValidator(strToValidate string) bool {
	s := SignedCheckpoint{}
	return s.UnmarshalText([]byte(strToValidate)) == nil
}

func CheckpointValidator(strToValidate string) bool {
	c := Checkpoint{}
	return c.UnmarshalText([]byte(strToValidate)) == nil
}

type RekorSTH struct {
	SignedCheckpoint
}

func (r *RekorSTH) SetTimestamp(timestamp uint64) {
	var ts uint64
	for i, val := range r.OtherContent {
		if n, _ := fmt.Fscanf(strings.NewReader(val), "Timestamp: %d", &ts); n == 1 {
			r.OtherContent = append(r.OtherContent[:i], r.OtherContent[i+1:]...)
		}
	}
	r.OtherContent = append(r.OtherContent, fmt.Sprintf("Timestamp: %d", timestamp))
}

func (r *RekorSTH) GetTimestamp() uint64 {
	var ts uint64
	for _, val := range r.OtherContent {
		if n, _ := fmt.Fscanf(strings.NewReader(val), "Timestamp: %d", &ts); n == 1 {
			break
		}
	}
	return ts
}

func RekorSTHValidator(strToValidate string) bool {
	r := RekorSTH{}
	return r.UnmarshalText([]byte(strToValidate)) == nil
}
