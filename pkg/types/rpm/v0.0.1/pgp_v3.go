//
// Copyright 2026 The Sigstore Authors.
// Portions derived from go-rpmutils, Copyright (c) SAS Institute Inc.
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

package rpm

import (
	"bytes"
	"crypto"
	_ "crypto/md5"  //nolint:gosec // Required to validate payloads of legacy RPMs.
	_ "crypto/sha1" //nolint:gosec // Required to validate payloads of legacy RPMs.
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/sassoftware/go-rpmutils"

	"github.com/sigstore/rekor/internal/pgpv3"
)

type rpmSignatureRegion struct {
	tag        int
	headerOnly bool
}

var rpmSignatureRegions = []rpmSignatureRegion{
	{tag: rpmutils.SIG_RSA, headerOnly: true},
	{tag: rpmutils.SIG_DSA, headerOnly: true},
	{tag: rpmutils.SIG_PGP, headerOnly: false},
	{tag: rpmutils.SIG_GPG, headerOnly: false},
}

// verifyRPM uses the upstream verifier unless an RPM contains a v3 signature.
// ReadHeader validates the general-header digest in both paths. The legacy
// path must also validate the payload digest and every signature tag.
func verifyRPM(packageBytes []byte, keyring openpgp.EntityList) (*rpmutils.RpmHeader, int, error) {
	v3Header, err := rpmHeaderWithV3Signature(packageBytes)
	if err != nil {
		return nil, 0, err
	}
	if v3Header == nil {
		header, signatures, err := rpmutils.Verify(bytes.NewReader(packageBytes), keyring)
		return header, len(signatures), err
	}
	signatureCount, v3Err := verifyRPMWithV3(packageBytes, v3Header, keyring)
	if v3Err != nil {
		return nil, 0, v3Err
	}
	return v3Header, signatureCount, nil
}

func rpmHeaderWithV3Signature(packageBytes []byte) (*rpmutils.RpmHeader, error) {
	header, err := rpmutils.ReadHeader(bytes.NewReader(packageBytes))
	if err != nil {
		return nil, err
	}
	for _, region := range rpmSignatureRegions {
		encoded, err := header.GetBytes(region.tag)
		if isMissingRPMTag(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, err := pgpv3.ParseStrict(encoded); err == nil {
			return header, nil
		} else if !errors.Is(err, pgpv3.ErrNotV3) {
			return nil, err
		}
	}
	return nil, nil
}

func verifyRPMWithV3(packageBytes []byte, header *rpmutils.RpmHeader, keyring openpgp.EntityList) (int, error) {
	headerRange := header.GetRange()
	if headerRange.Start < 0 || headerRange.Start > headerRange.End || headerRange.End > len(packageBytes) {
		return 0, errors.New("invalid RPM header range")
	}
	if err := verifyRPMPayloadDigest(header, packageBytes[headerRange.Start:headerRange.End], packageBytes[headerRange.End:]); err != nil {
		return 0, err
	}

	signatureCount := 0
	for _, region := range rpmSignatureRegions {
		encoded, err := header.GetBytes(region.tag)
		if isMissingRPMTag(err) {
			continue
		}
		if err != nil {
			return 0, err
		}

		signedBytes := packageBytes[headerRange.Start:]
		if region.headerOnly {
			signedBytes = packageBytes[headerRange.Start:headerRange.End]
		}
		v3Signature, err := pgpv3.ParseStrict(encoded)
		switch {
		case err == nil:
			if _, err := v3Signature.VerifyDetached(keyring.KeysById(v3Signature.IssuerKeyID), bytes.NewReader(signedBytes)); err != nil {
				return 0, err
			}
		case errors.Is(err, pgpv3.ErrNotV3):
			if err := verifyRPMModernSignature(encoded, signedBytes, keyring); err != nil {
				return 0, err
			}
		default:
			return 0, err
		}
		signatureCount++
	}

	return signatureCount, nil
}

// verifyRPMModernSignature preserves go-rpmutils' direct packet verification
// for modern signatures in an RPM that also contains a legacy signature.
// RPM verification does not apply the detached verifier's key expiry policy.
func verifyRPMModernSignature(encoded, signed []byte, keyring openpgp.EntityList) error {
	r := bytes.NewReader(encoded)
	p, err := packet.Read(r)
	if err != nil {
		return err
	}
	if r.Len() != 0 {
		return rpmutils.ErrTrailingGarbage
	}
	sig, ok := p.(*packet.Signature)
	if !ok || (sig.IssuerKeyId == nil && len(sig.IssuerFingerprint) == 0) {
		return rpmutils.ErrNoPGPSignature
	}
	if !sig.Hash.Available() {
		return fmt.Errorf("unsupported RPM signature hash %v", sig.Hash)
	}
	for _, entity := range keyring {
		if entity == nil {
			continue
		}
		keys := []*packet.PublicKey{entity.PrimaryKey}
		for _, sub := range entity.Subkeys {
			keys = append(keys, sub.PublicKey)
		}
		for _, key := range keys {
			if key != nil && sig.CheckKeyIdOrFingerprint(key) {
				h := sig.Hash.New()
				_, _ = h.Write(signed)
				return key.VerifySignature(h, sig)
			}
		}
	}
	keyID := uint64(0)
	if sig.IssuerKeyId != nil {
		keyID = *sig.IssuerKeyId
	}
	return rpmutils.KeyNotFoundError{KeyID: keyID, Fingerprint: sig.IssuerFingerprint}
}

func verifyRPMPayloadDigest(header *rpmutils.RpmHeader, generalHeader, payload []byte) error {
	digests, digestErr := header.GetStrings(rpmutils.PAYLOADDIGEST)
	algorithms, algorithmErr := header.GetUint32s(rpmutils.PAYLOADDIGESTALGO)
	if digestErr == nil && algorithmErr == nil && len(digests) > 0 && len(algorithms) > 0 {
		// Like go-rpmutils, treat an unrecognized algorithm as no payload
		// digest and fall back to SIG_MD5 over the header and payload below.
		if hashAlgorithm, ok := rpmHash(algorithms[0]); ok {
			if !hashAlgorithm.Available() {
				return fmt.Errorf("unknown RPM payload digest algorithm %d", algorithms[0])
			}
			h := hashAlgorithm.New()
			if _, err := h.Write(payload); err != nil {
				return err
			}
			if calculated := hex.EncodeToString(h.Sum(nil)); calculated != digests[0] {
				return fmt.Errorf("payload %s digest mismatch", hashAlgorithm)
			}
			return nil
		}
	}

	expectedMD5, err := header.GetBytes(rpmutils.SIG_MD5)
	if err != nil {
		return errors.New("no usable payload digest found")
	}
	h := crypto.MD5.New() //nolint:gosec // Compatibility check for legacy RPM metadata.
	if _, err := h.Write(generalHeader); err != nil {
		return err
	}
	if _, err := h.Write(payload); err != nil {
		return err
	}
	if !bytes.Equal(h.Sum(nil), expectedMD5) {
		return errors.New("md5 digest mismatch")
	}
	return nil
}

func rpmHash(id uint32) (crypto.Hash, bool) {
	switch id {
	case rpmutils.HASH_MD5:
		return crypto.MD5, true
	case rpmutils.HASH_SHA1:
		return crypto.SHA1, true
	case rpmutils.HASH_SHA224:
		return crypto.SHA224, true
	case rpmutils.HASH_SHA256:
		return crypto.SHA256, true
	case rpmutils.HASH_SHA384:
		return crypto.SHA384, true
	case rpmutils.HASH_SHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func isMissingRPMTag(err error) bool {
	var missing rpmutils.NoSuchTagError
	return errors.As(err, &missing)
}
