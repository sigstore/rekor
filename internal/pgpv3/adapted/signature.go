// Copyright 2011, 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package adapted contains the v3 parser and verifier adapted from pgpkeys-eu.
// Source paths below are relative to github.com/pgpkeys-eu/go-crypto at commit
// d2a8cc303a65a5643c299cb0ffde2ced6f1e14ee. Each declaration identifies its
// upstream source and changes; inline "Local change" comments mark behavioral
// differences. See ../UPSTREAM.md for the complete provenance map.
package adapted

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // Required to verify legacy DSA signatures.
	"crypto/rsa"
	"encoding/binary"
	"hash"
	"io"
	"math/big"
	"strconv"
	"time"

	// Local integration: register the hash implementations used by legacy signatures.
	_ "crypto/md5"  //nolint:gosec // Required to verify historical signatures.
	_ "crypto/sha1" //nolint:gosec // Required to verify historical signatures.
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"

	"github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/sigstore/rekor/internal/pgpv3/upstream/algorithm"
	"github.com/sigstore/rekor/internal/pgpv3/upstream/encoding"
)

// Signature is a version 3 OpenPGP signature packet.
//
// Upstream: openpgp/packet/signature_v3.go, SignatureV3.
// Local changes: rename the type and IssuerKeyId field, qualify ProtonMail's
// enum types, and store MPI bytes instead of upstream's internal encoding.Field.
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

// Upstream: openpgp/packet/packet.go, readFull.
// Local change: drop the byte-count return value; preserve EOF handling.
func readFull(r io.Reader, buf []byte) error {
	_, err := io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// Parse reads a version 3 signature packet from contents, which must be the
// packet body with the OpenPGP packet header already stripped.
//
// Upstream: openpgp/packet/signature_v3.go, (*SignatureV3).parse.
// Local changes: allocate and return a Signature from a byte slice instead of
// filling a receiver from an io.Reader; rewrite field reads and error returns
// for the local types and readSignatureMPI helper; reject trailing body bytes.
// The hash lookup and MPI decoder are unchanged copies in ../upstream/.
func Parse(contents []byte) (*Signature, error) {
	r := bytes.NewReader(contents)
	sig := new(Signature)
	var buf [8]byte

	if err := readFull(r, buf[:1]); err != nil {
		return nil, err
	}
	if buf[0] < 2 || buf[0] > 3 {
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
	if sig.Hash, ok = algorithm.HashIdToHashWithSha1Md5(buf[1]); !ok {
		return nil, errors.UnsupportedError("hash function " + strconv.Itoa(int(buf[1])))
	}

	// Left 16 bits of the signed hash value.
	if err := readFull(r, sig.HashTag[:]); err != nil {
		return nil, err
	}

	var err error
	switch sig.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		sig.RSASignature, err = readSignatureMPI(r)
	case packet.PubKeyAlgoDSA:
		if sig.DSASigR, err = readSignatureMPI(r); err != nil {
			return nil, err
		}
		sig.DSASigS, err = readSignatureMPI(r)
	}
	if err != nil {
		return nil, err
	}
	// Local change: upstream does not reject leftover bytes in the packet body.
	if r.Len() != 0 {
		return nil, errors.StructuralError("trailing data in v3 signature packet")
	}
	return sig, nil
}

// PrepareVerify returns an empty hash object for the signature's algorithm.
//
// Upstream: openpgp/packet/signature_v3.go, (*SignatureV3).PrepareVerify.
// Unchanged body; only the receiver type is renamed.
func (sig *Signature) PrepareVerify() (hash.Hash, error) {
	if !sig.Hash.Available() {
		return nil, errors.UnsupportedError("hash function")
	}
	return sig.Hash.New(), nil
}

// padToKeySize left-pads b with zeroes to the modulus size of pub.
//
// Upstream: openpgp/packet/packet.go, padToKeySize.
// Unchanged function declaration and body; this comment is local.
func padToKeySize(pub *rsa.PublicKey, b []byte) []byte {
	k := (pub.N.BitLen() + 7) / 8
	if len(b) >= k {
		return b
	}
	bb := make([]byte, k)
	copy(bb[len(bb)-len(b):], b)
	return bb
}

// Verify reports whether sig is a valid signature by pk over the data already
// written into signed. signed is mutated by this call.
//
// Upstream: openpgp/packet/public_key_v3.go, (*PublicKey).VerifySignatureV3
// (the v4 public-key method, not (*PublicKeyV3).VerifySignatureV3).
// Local changes: move the receiver to Signature, accept a ProtonMail key, use
// byte slices instead of encoding.Field.Bytes(), and use explicit error returns.
// Additional error checks are marked below. The signature trailer, hash-tag
// check, algorithm match, and RSA/DSA verification math follow upstream.
func (sig *Signature) Verify(signed hash.Hash, pk *packet.PublicKey) error {
	// Local change: return an error for a nil key instead of dereferencing it.
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
	// Local change: propagate the hash-write error, which upstream ignores.
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
		// Local change: check the type assertion instead of allowing a panic.
		if !ok {
			return errors.InvalidArgumentError("public key algorithm mismatch")
		}
		if err := rsa.VerifyPKCS1v15(rsaPublicKey, sig.Hash, hashBytes, padToKeySize(rsaPublicKey, sig.RSASignature)); err != nil {
			return errors.SignatureError("RSA verification failure")
		}
		return nil
	case packet.PubKeyAlgoDSA:
		dsaPublicKey, ok := pk.PublicKey.(*dsa.PublicKey)
		// Local change: check the type assertion instead of allowing a panic.
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
		// Local change: return an unsupported-algorithm error instead of panicking.
		return errors.UnsupportedError("public key algorithm " + strconv.Itoa(int(pk.PubKeyAlgo)))
	}
}

// readSignatureMPI adapts the unchanged upstream MPI decoder to Signature.
// Locally authored wrapper; no corresponding upstream declaration. Decoding is
// delegated to openpgp/internal/encoding/mpi.go, (*MPI).ReadFrom, copied unchanged
// into ../upstream/encoding/mpi.go.
func readSignatureMPI(r io.Reader) ([]byte, error) {
	var mpi encoding.MPI
	if _, err := mpi.ReadFrom(r); err != nil {
		return nil, err
	}
	return mpi.Bytes(), nil
}
