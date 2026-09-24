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

package rpm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	protonpacket "github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/sassoftware/go-rpmutils"
)

func TestVerifyRPMV3Signatures(t *testing.T) {
	packageBytes := mustReadFile(t, "../tests/test.rpm")
	header, err := rpmutils.ReadHeader(bytes.NewReader(packageBytes))
	if err != nil {
		t.Fatal(err)
	}
	headerRange := header.GetRange()

	privateBytes := mustReadFile(t, "../../../pki/pgp/testdata/armored_private.pgp")
	privateKeyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(privateBytes))
	if err != nil {
		t.Fatal(err)
	}
	entity := privateKeyring[0]
	creationTime := time.Unix(1700000000, 0)
	payloadSignature := makeV3RSASignature(t, packageBytes[headerRange.Start:], entity, creationTime)
	headerSignature := makeV3RSASignature(t, packageBytes[headerRange.Start:headerRange.End], entity, creationTime)

	publicBytes := mustReadFile(t, "../../../pki/pgp/testdata/valid_armored_public.pgp")
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(publicBytes))
	if err != nil {
		t.Fatal(err)
	}
	modern := new(bytes.Buffer)
	cfg := &protonpacket.Config{Time: func() time.Time { return entity.PrimaryKey.CreationTime }}
	if err := openpgp.DetachSign(modern, entity, bytes.NewReader(packageBytes[headerRange.Start:headerRange.End]), cfg); err != nil {
		t.Fatal(err)
	}
	badV3 := append([]byte(nil), headerSignature...)
	badV3[len(badV3)-1] ^= 1
	badModern := append([]byte(nil), modern.Bytes()...)
	badModern[len(badModern)-1] ^= 1

	for _, tc := range []struct {
		name            string
		headerSignature []byte
		tamperPayload   bool
		wrongKey        bool
		wantErr         bool
	}{
		{name: "v3 header and payload", headerSignature: headerSignature},
		{name: "mixed v3 payload and v4 header", headerSignature: modern.Bytes()},
		{name: "invalid v3 header", headerSignature: badV3, wantErr: true},
		{name: "invalid v4 header", headerSignature: badModern, wantErr: true},
		{name: "trailing v3 packet", headerSignature: append(append([]byte(nil), headerSignature...), headerSignature...), wantErr: true},
		{name: "trailing v4 packet", headerSignature: append(append([]byte(nil), modern.Bytes()...), modern.Bytes()...), wantErr: true},
		{name: "truncated v3", headerSignature: headerSignature[:10], wantErr: true},
		{name: "tampered payload", headerSignature: headerSignature, tamperPayload: true, wantErr: true},
		{name: "wrong key", headerSignature: headerSignature, wrongKey: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v3Package := rewriteSignatures(t, packageBytes, payloadSignature, tc.headerSignature)
			if tc.tamperPayload {
				v3Package[len(v3Package)-1] ^= 1
			}
			knownKeys := keyring
			if tc.wrongKey {
				var err error
				knownKeys, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(mustReadFile(t, "../../../pki/pgp/testdata/repomd_armored_public.pgp")))
				if err != nil {
					t.Fatal(err)
				}
			}
			verifiedHeader, signatureCount, err := verifyRPM(v3Package, knownKeys)
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted invalid RPM")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if verifiedHeader == nil || signatureCount != 2 {
				t.Fatalf("header=%v signatures=%d, want a header and two signatures", verifiedHeader, signatureCount)
			}
		})
	}
}

func rewriteSignatures(t *testing.T, data, payloadSignature, headerSignature []byte) []byte {
	t.Helper()
	inputPath := filepath.Join(t.TempDir(), "input.rpm")
	outputPath := filepath.Join(t.TempDir(), "signed.rpm")
	if err := os.WriteFile(inputPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := rpmutils.RewriteWithSignatures(input, outputPath, payloadSignature, headerSignature); err != nil {
		t.Fatal(err)
	}
	return mustReadFile(t, outputPath)

}

func makeV3RSASignature(t *testing.T, signed []byte, entity *openpgp.Entity, creationTime time.Time) []byte {
	t.Helper()
	privateKey, ok := entity.PrivateKey.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key has type %T, want *rsa.PrivateKey", entity.PrivateKey.PrivateKey)
	}

	h := sha256.New()
	if _, err := h.Write(signed); err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 5)
	suffix[0] = byte(protonpacket.SigTypeBinary)
	binary.BigEndian.PutUint32(suffix[1:], uint32(creationTime.Unix()))
	if _, err := h.Write(suffix); err != nil {
		t.Fatal(err)
	}
	digest := h.Sum(nil)
	rsaSignature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}

	body := new(bytes.Buffer)
	body.WriteByte(3)
	body.WriteByte(5)
	body.Write(suffix)
	if err := binary.Write(body, binary.BigEndian, entity.PrimaryKey.KeyId); err != nil {
		t.Fatal(err)
	}
	body.WriteByte(byte(protonpacket.PubKeyAlgoRSA))
	body.WriteByte(8) // SHA-256, RFC 4880 section 9.4.
	body.Write(digest[:2])
	if err := binary.Write(body, binary.BigEndian, uint16(new(big.Int).SetBytes(rsaSignature).BitLen())); err != nil {
		t.Fatal(err)
	}
	body.Write(rsaSignature)

	packet := new(bytes.Buffer)
	packet.WriteByte(0x89) // Old-format signature packet with a two-octet length.
	if err := binary.Write(packet, binary.BigEndian, uint16(body.Len())); err != nil {
		t.Fatal(err)
	}
	packet.Write(body.Bytes())
	return packet.Bytes()
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
