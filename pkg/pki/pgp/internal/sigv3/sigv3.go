// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sigv3 reads and verifies version 3 OpenPGP signature packets
// (RFC 4880, section 5.2.2).
//
// github.com/ProtonMail/go-crypto dropped v3 signature support in v1.4.x, but
// Rekor must keep verifying entries already recorded in the transparency log.
// The code here is derived from that project's signature_v3.go and
// public_key_v3.go, reduced to the verification path Rekor needs and rewritten
// against its exported API so no forked module is required.
//
// Only verification of a v3 signature made by a v4 public key is supported;
// v3 public keys and v3 signature generation are deliberately omitted.
package sigv3

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // required to verify legacy DSA signatures already in the log
	"crypto/rsa"
	"encoding"
	"encoding/binary"
	"hash"
	"io"
	"math/big"
	"strconv"
	"time"

	// Link the hash implementations named in hashIDToHash. crypto.Hash.New
	// panics unless the algorithm is registered, and openpgp only links a
	// subset, so this package registers the ones it claims to support rather
	// than depending on another package's imports.
	_ "crypto/md5"  //nolint:gosec // legacy v3 signatures in the log may use MD5
	_ "crypto/sha1" //nolint:gosec // legacy v3 signatures in the log may use SHA-1
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// hashIDToHash maps OpenPGP hash identifiers to Go hash functions. MD5 and
// SHA-1 are included because v3 signatures predate their deprecation.
var hashIDToHash = map[byte]crypto.Hash{
	1:  crypto.MD5,
	2:  crypto.SHA1,
	8:  crypto.SHA256,
	9:  crypto.SHA384,
	10: crypto.SHA512,
	11: crypto.SHA224,
	12: crypto.SHA3_256,
	14: crypto.SHA3_512,
}

const (
	signaturePacketTag = 2
	minVersion         = 2
	maxVersion         = 3
)

// Signature is a version 3 OpenPGP signature packet.
type Signature struct {
	SigType      packet.SignatureType
	CreationTime time.Time
	IssuerKeyID  uint64
	PubKeyAlgo   packet.PublicKeyAlgorithm
	Hash         crypto.Hash
	HashTag      [2]byte

	RSASignature     []byte
	DSASigR, DSASigS []byte
}

// IsV3Packet reports whether contents is the body of a version 2 or 3
// signature packet. tag is the OpenPGP packet tag it was read under.
func IsV3Packet(tag uint8, contents []byte) bool {
	return tag == signaturePacketTag && len(contents) > 0 && contents[0] >= minVersion && contents[0] <= maxVersion
}

func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// readMPI reads a multiprecision integer and returns its big-endian bytes.
func readMPI(r io.Reader) ([]byte, error) {
	var lengthBytes [2]byte
	if err := readFull(r, lengthBytes[:]); err != nil {
		return nil, err
	}
	bitLength := uint16(lengthBytes[0])<<8 | uint16(lengthBytes[1])
	b := make([]byte, (int(bitLength)+7)/8)
	if err := readFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// Parse reads a version 3 signature packet from contents, which must be the
// packet body with the OpenPGP packet header already stripped.
func Parse(contents []byte) (*Signature, error) {
	r := bytes.NewReader(contents)
	sig := new(Signature)
	var buf [8]byte

	if err := readFull(r, buf[:1]); err != nil {
		return nil, err
	}
	if buf[0] < minVersion || buf[0] > maxVersion {
		return nil, errors.UnsupportedError("signature packet version " + strconv.Itoa(int(buf[0])))
	}

	if err := readFull(r, buf[:1]); err != nil {
		return nil, err
	}
	if buf[0] != 5 {
		return nil, errors.UnsupportedError("invalid hashed material length " + strconv.Itoa(int(buf[0])))
	}

	// Hashed material: signature type followed by creation time.
	if err := readFull(r, buf[:5]); err != nil {
		return nil, err
	}
	sig.SigType = packet.SignatureType(buf[0])
	sig.CreationTime = time.Unix(int64(binary.BigEndian.Uint32(buf[1:5])), 0)

	if err := readFull(r, buf[:8]); err != nil {
		return nil, err
	}
	sig.IssuerKeyID = binary.BigEndian.Uint64(buf[:8])

	if err := readFull(r, buf[:2]); err != nil {
		return nil, err
	}
	sig.PubKeyAlgo = packet.PublicKeyAlgorithm(buf[0])
	switch sig.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoDSA:
	default:
		return nil, errors.UnsupportedError("public key algorithm " + strconv.Itoa(int(sig.PubKeyAlgo)))
	}

	var ok bool
	if sig.Hash, ok = hashIDToHash[buf[1]]; !ok {
		return nil, errors.UnsupportedError("hash function " + strconv.Itoa(int(buf[1])))
	}

	// Left 16 bits of the signed hash value.
	if err := readFull(r, sig.HashTag[:]); err != nil {
		return nil, err
	}

	var err error
	switch sig.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		sig.RSASignature, err = readMPI(r)
	case packet.PubKeyAlgoDSA:
		if sig.DSASigR, err = readMPI(r); err != nil {
			return nil, err
		}
		sig.DSASigS, err = readMPI(r)
	}
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// PrepareVerify returns an empty hash object for the signature's algorithm.
func (sig *Signature) PrepareVerify() (hash.Hash, error) {
	if !sig.Hash.Available() {
		return nil, errors.UnsupportedError("hash function")
	}
	return sig.Hash.New(), nil
}

// padToKeySize left-pads b with zeroes to the modulus size of pub.
func padToKeySize(pub *rsa.PublicKey, b []byte) []byte {
	k := (pub.N.BitLen() + 7) / 8
	if len(b) >= k {
		return b
	}
	bb := make([]byte, k)
	copy(bb[len(bb)-len(b):], b)
	return bb
}

// verify reports whether sig is a valid signature by pk over the data already
// written into signed. signed is mutated by this call.
func (sig *Signature) verify(signed hash.Hash, pk *packet.PublicKey) error {
	if pk == nil {
		return errors.InvalidArgumentError("no public key provided")
	}
	if !pk.CanSign() {
		return errors.InvalidArgumentError("public key cannot generate signatures")
	}

	// A v3 signature hashes a 5-octet trailer of signature type and creation time.
	suffix := make([]byte, 5)
	suffix[0] = byte(sig.SigType)
	binary.BigEndian.PutUint32(suffix[1:], uint32(sig.CreationTime.Unix()))
	if _, err := signed.Write(suffix); err != nil {
		return err
	}
	hashBytes := signed.Sum(nil)

	if hashBytes[0] != sig.HashTag[0] || hashBytes[1] != sig.HashTag[1] {
		return errors.SignatureError("hash tag doesn't match")
	}

	if pk.PubKeyAlgo != sig.PubKeyAlgo {
		return errors.InvalidArgumentError("public key and signature use different algorithms")
	}

	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		rsaPublicKey, ok := pk.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("public key algorithm mismatch")
		}
		if err := rsa.VerifyPKCS1v15(rsaPublicKey, sig.Hash, hashBytes, padToKeySize(rsaPublicKey, sig.RSASignature)); err != nil {
			return errors.SignatureError("RSA verification failure")
		}
		return nil
	case packet.PubKeyAlgoDSA:
		dsaPublicKey, ok := pk.PublicKey.(*dsa.PublicKey)
		if !ok {
			return errors.InvalidArgumentError("public key algorithm mismatch")
		}
		// Truncate to the subgroup size, per FIPS 186-3 section 4.6.
		subgroupSize := (dsaPublicKey.Q.BitLen() + 7) / 8
		if len(hashBytes) > subgroupSize {
			hashBytes = hashBytes[:subgroupSize]
		}
		if !dsa.Verify(dsaPublicKey, hashBytes, new(big.Int).SetBytes(sig.DSASigR), new(big.Int).SetBytes(sig.DSASigS)) {
			return errors.SignatureError("DSA verification failure")
		}
		return nil
	default:
		return errors.UnsupportedError("public key algorithm " + strconv.Itoa(int(pk.PubKeyAlgo)))
	}
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
		if err = sig.verify(h, key.PublicKey); err == nil {
			return key.Entity, nil
		}
	}
	return nil, err
}
