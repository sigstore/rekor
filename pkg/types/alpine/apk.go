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

package alpine

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

type Package struct {
	Pkginfo           map[string]string // KVP pairs
	Signature         []byte
	Datahash          []byte
	controlSHA1Digest []byte
}

type sha1Reader struct {
	r         *bufio.Reader
	addToHash bool
	hasher    hash.Hash
}

func newSHA1Reader(b *bufio.Reader) *sha1Reader {
	// #nosec G401
	c := sha1Reader{
		r:      b,
		hasher: sha1.New(),
	}
	return &c
}

func (s *sha1Reader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err == nil && n > 0 && s.addToHash {
		s.hasher.Write(p)
	}
	return n, err
}

func (s *sha1Reader) ReadByte() (byte, error) {
	b, err := s.r.ReadByte()
	if err == nil && s.addToHash {
		s.hasher.Write([]byte{b})
	}
	return b, err
}

func (s sha1Reader) Sum() []byte {
	return s.hasher.Sum(nil)
}

func (s *sha1Reader) StartHashing() {
	s.hasher.Reset()
	s.addToHash = true
}

func (s *sha1Reader) StopHashing() {
	s.addToHash = false
}

func (p *Package) Unmarshal(pkgReader io.Reader) error {
	pkg := Package{}
	// bufio.Reader is required if Multistream(false) is used
	bufReader := bufio.NewReader(pkgReader)
	sha1BufReader := newSHA1Reader(bufReader)
	gzipReader, err := gzip.NewReader(sha1BufReader)
	if err != nil {
		return errors.Wrap(err, "create gzip reader")
	}
	defer func() {
		_ = gzipReader.Close()
	}()

	// APKs are concatenated gzip files so we want to know where the boundary is
	gzipReader.Multistream(false)

	// GZIP headers/footers are left unmodified; Tar footers are removed on first two archives
	// signature.tar.gz | control.tar.gz | data.tar.gz
	sigBuf := bytes.Buffer{}
	// #nosec G110
	if _, err := io.Copy(&sigBuf, gzipReader); err != nil {
		return errors.Wrap(err, "reading signature.tar.gz")
	}

	// the SHA1 sum used in the signature is over the entire file control.tar.gz so we need to
	// intercept the buffered reading to compute the hash correctly
	//
	// we start sha1 hashing now since the Reset() call will begin reading control.tar.gz headers
	sha1BufReader.StartHashing()

	// we reset the reader since we've found the end of signature.tar.gz
	if err := gzipReader.Reset(sha1BufReader); err != nil && err != io.EOF {
		return errors.Wrap(err, "resetting to control.tar.gz")
	}
	gzipReader.Multistream(false)

	controlTar := bytes.Buffer{}
	// #nosec G110
	if _, err = io.Copy(&controlTar, gzipReader); err != nil {
		return errors.Wrap(err, "reading control.tar.gz")
	}

	// signature uses sha1 digest hardcoded in abuild-sign tool
	pkg.controlSHA1Digest = sha1BufReader.Sum()
	sha1BufReader.StopHashing()

	// the gzip reader is NOT reset again since that advances the underlying reader
	// by reading the next GZIP header, which affects the datahash computation below

	sigReader := tar.NewReader(&sigBuf)
	for {
		header, err := sigReader.Next()
		if err == io.EOF {
			if pkg.Signature == nil {
				return errors.New("no signature detected in alpine package")
			}
			break
		} else if err != nil {
			return errors.Wrap(err, "getting next entry in tar archive")
		}

		if strings.HasPrefix(header.Name, ".SIGN") && pkg.Signature == nil {
			sigBytes := make([]byte, header.Size)
			if _, err = sigReader.Read(sigBytes); err != nil && err != io.EOF {
				return errors.Wrap(err, "reading signature")
			}
			// we're not sure whether this is PEM encoded or not, so handle both cases
			block, _ := pem.Decode(sigBytes)
			if block == nil {
				pkg.Signature = sigBytes
			} else {
				pkg.Signature = block.Bytes
			}
		}
	}

	ctlReader := tar.NewReader(&controlTar)
	for {
		header, err := ctlReader.Next()
		if err == io.EOF {
			if pkg.Pkginfo == nil {
				return errors.New(".PKGINFO file was not located")
			}
			break
		} else if err != nil {
			return errors.Wrap(err, "getting next entry in tar archive")
		}

		if header.Name == ".PKGINFO" {
			pkginfoContent := make([]byte, header.Size)
			if _, err = ctlReader.Read(pkginfoContent); err != nil && err != io.EOF {
				return errors.Wrap(err, "reading .PKGINFO")
			}

			pkg.Pkginfo, err = parsePkginfo(pkginfoContent)
			if err != nil {
				return errors.Wrap(err, "parsing .PKGINFO")
			}
			pkg.Datahash, err = hex.DecodeString(pkg.Pkginfo["datahash"])
			if err != nil {
				return errors.Wrap(err, "parsing datahash")
			}
		}
	}

	// at this point, bufReader should point to first byte of data.tar.gz
	// datahash value from .PKGINFO is sha256 sum of data.tar.gz
	sha256 := sha256.New()
	if _, err := io.Copy(sha256, bufReader); err != nil {
		return errors.Wrap(err, "computing SHA256 sum of data.tar.gz")
	}
	computedSum := sha256.Sum(nil)

	if !bytes.Equal(computedSum, pkg.Datahash) {
		return fmt.Errorf("checksum for data.tar.gz (%v) does not match value from .PKGINFO (%v)", hex.EncodeToString(computedSum), hex.EncodeToString(pkg.Datahash))
	}
	*p = pkg
	return nil
}

// VerifySignature verifies the signature of the alpine package using the provided
// public key. It returns an error if verification fails, or nil if it is successful.
func (p Package) VerifySignature(pub crypto.PublicKey) error {
	if p.Signature == nil {
		return errors.New("no signature in alpine package object")
	}
	if p.controlSHA1Digest == nil {
		return errors.New("no digest value for data.tar.gz known")
	}

	switch pk := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pk, crypto.SHA1, p.controlSHA1Digest, p.Signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pk, p.controlSHA1Digest, p.Signature) {
			return errors.New("failed to verify ECDSA signature")
		}
	default:
		return errors.New("unknown key algorithm")
	}
	return nil
}

// parsePkginfo parses the .PKGINFO file which is in a
// key[space]=[space]value\n
// format. it returns a map[string]string of the key/value pairs, or
// an error if parsing could not be completed successfully.
func parsePkginfo(input []byte) (map[string]string, error) {
	cfg, err := ini.Load(input)
	if err != nil {
		return nil, err
	}

	// .PKGINFO does not use sections, so using "" grabs the default values
	return cfg.Section("").KeysHash(), nil
}
