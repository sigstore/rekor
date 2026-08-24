//
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

package sigv3

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // exercises legacy DSA verification
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func v3Fixture(t *testing.T) (*Signature, []byte, openpgp.EntityList) {
	t.Helper()

	sigPacket, err := os.ReadFile("../../testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(bytes.NewReader(sigPacket)).Next()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Parse(op.Contents)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("../../testdata/repomd.xml")
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile("../../testdata/repomd_armored_public.pgp")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyData))
	if err != nil {
		t.Fatal(err)
	}
	return sig, data, keyring
}

// Parse rejects any hash it cannot construct, so an unlinked algorithm would
// silently stop legacy log entries from verifying rather than fail loudly.
func TestDeclaredHashesAreLinked(t *testing.T) {
	for id, h := range hashIDToHash {
		if !h.Available() {
			t.Errorf("hash id %d (%v) is declared supported but not linked into the binary", id, h)
		}
	}
}

func TestIsV3Packet(t *testing.T) {
	for _, tc := range []struct {
		desc     string
		tag      uint8
		contents []byte
		want     bool
	}{
		{"v3 signature", 2, []byte{3, 5}, true},
		{"v2 signature", 2, []byte{2, 5}, true},
		{"v4 signature", 2, []byte{4}, false},
		{"v6 signature", 2, []byte{6}, false},
		{"non-signature tag", 6, []byte{3}, false},
		{"empty contents", 2, nil, false},
	} {
		if got := IsV3Packet(tc.tag, tc.contents); got != tc.want {
			t.Errorf("%s: IsV3Packet(%d, %v) = %v, want %v", tc.desc, tc.tag, tc.contents, got, tc.want)
		}
	}
}

func TestParse(t *testing.T) {
	sigPacket, err := os.ReadFile("../../testdata/repomd.xml.sig")
	if err != nil {
		t.Fatal(err)
	}
	op, err := packet.NewOpaqueReader(bytes.NewReader(sigPacket)).Next()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Parse(op.Contents)
	if err != nil {
		t.Fatal(err)
	}
	if sig.IssuerKeyID != 0x70af9e8139db7c82 {
		t.Errorf("issuer key ID = %x", sig.IssuerKeyID)
	}
	if sig.PubKeyAlgo != packet.PubKeyAlgoRSA || sig.Hash != crypto.SHA256 || len(sig.RSASignature) == 0 {
		t.Errorf("unexpected parsed signature: algorithm=%v hash=%v signature bytes=%d", sig.PubKeyAlgo, sig.Hash, len(sig.RSASignature))
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated", func(body []byte) []byte { return body[:18] }},
		{"bad version", func(body []byte) []byte { body[0] = 4; return body }},
		{"bad hashed material length", func(body []byte) []byte { body[1] = 4; return body }},
		{"unsupported public key algorithm", func(body []byte) []byte { body[15] = 99; return body }},
		{"unknown hash", func(body []byte) []byte { body[16] = 99; return body }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := append([]byte(nil), op.Contents...)
			if _, err := Parse(tc.mutate(body)); err == nil {
				t.Fatal("Parse succeeded")
			}
		})
	}
}

func TestVerifyRejectsInvalidInputs(t *testing.T) {
	sig, data, keyring := v3Fixture(t)
	keys := keyring.KeysByIdUsage(sig.IssuerKeyID, packet.KeyFlagSign)
	if len(keys) == 0 {
		t.Fatal("fixture keyring does not contain signing key")
	}

	t.Run("hash tag mismatch", func(t *testing.T) {
		badSig := *sig
		badSig.HashTag[0] ^= 0xff
		h, err := badSig.PrepareVerify()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(data)
		if err := badSig.verify(h, keys[0].PublicKey); err == nil {
			t.Fatal("verification succeeded")
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		badKey := *keys[0].PublicKey
		badKey.PubKeyAlgo = packet.PubKeyAlgoDSA
		h, err := sig.PrepareVerify()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(data)
		if err := sig.verify(h, &badKey); err == nil {
			t.Fatal("verification succeeded")
		}
	})

	t.Run("key cannot sign", func(t *testing.T) {
		badKey := *keys[0].PublicKey
		badKey.PubKeyAlgo = packet.PubKeyAlgoRSAEncryptOnly
		h, err := sig.PrepareVerify()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(data)
		if err := sig.verify(h, &badKey); err == nil {
			t.Fatal("verification succeeded")
		}
	})
}

func TestVerifyDetachedRestoresHashForNextKey(t *testing.T) {
	sig, data, keyring := v3Fixture(t)
	keys := keyring.KeysByIdUsage(sig.IssuerKeyID, packet.KeyFlagSign)
	if len(keys) == 0 {
		t.Fatal("fixture keyring does not contain signing key")
	}

	wrong := keys[0]
	wrongPacket := *wrong.PublicKey
	wrongRSA := *wrongPacket.PublicKey.(*rsa.PublicKey)
	wrongRSA.N = new(big.Int).Add(wrongRSA.N, big.NewInt(2))
	wrongPacket.PublicKey = &wrongRSA
	wrong.PublicKey = &wrongPacket

	entity, err := sig.VerifyDetached([]openpgp.Key{wrong, keys[0]}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if entity != keys[0].Entity {
		t.Fatal("verification returned the wrong entity")
	}
}

func TestVerifyDetachedRejectsUnsupportedSignatureType(t *testing.T) {
	sig, data, keyring := v3Fixture(t)
	keys := keyring.KeysByIdUsage(sig.IssuerKeyID, packet.KeyFlagSign)
	if len(keys) == 0 {
		t.Fatal("fixture keyring does not contain signing key")
	}
	sig.SigType = packet.SigTypeKeyRevocation
	if _, err := sig.VerifyDetached(keys, bytes.NewReader(data)); err == nil {
		t.Fatal("verification succeeded")
	}
}

func TestVerifyDSATruncatesHash(t *testing.T) {
	sig := &Signature{
		SigType:      packet.SigTypeBinary,
		CreationTime: time.Unix(1, 0),
		PubKeyAlgo:   packet.PubKeyAlgoDSA,
		Hash:         crypto.SHA256,
		DSASigR:      []byte{0},
		DSASigS:      []byte{0},
	}
	data := []byte("legacy DSA")
	h, err := sig.PrepareVerify()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.Write(data)
	var suffix [5]byte
	suffix[0] = byte(sig.SigType)
	binary.BigEndian.PutUint32(suffix[1:], uint32(sig.CreationTime.Unix()))
	_, _ = h.Write(suffix[:])
	copy(sig.HashTag[:], h.Sum(nil))

	h, err = sig.PrepareVerify()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = h.Write(data)
	pub := &packet.PublicKey{
		PubKeyAlgo: packet.PubKeyAlgoDSA,
		PublicKey: &dsa.PublicKey{
			Parameters: dsa.Parameters{P: big.NewInt(1), Q: big.NewInt(128), G: big.NewInt(1)},
			Y:          big.NewInt(1),
		},
	}
	if err := sig.verify(h, pub); err == nil {
		t.Fatal("invalid DSA signature verified")
	}
}
