// Copyright 2024 The Sigstore Authors.
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

package tink

// Copy of https://github.com/sigstore/fulcio/blob/a781da9903c63a2cd2c0f0c1c2bfc763196db44f/pkg/ca/tinkca/signer.go
// with a modification for including the hash function when creating the signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	commonpb "github.com/tink-crypto/tink-go/v2/proto/common_go_proto"
	ecdsapb "github.com/tink-crypto/tink-go/v2/proto/ecdsa_go_proto"
	ed25519pb "github.com/tink-crypto/tink-go/v2/proto/ed25519_go_proto"
	tinkpb "github.com/tink-crypto/tink-go/v2/proto/tink_go_proto"
	signatureSubtle "github.com/tink-crypto/tink-go/v2/signature/subtle"
	"github.com/tink-crypto/tink-go/v2/subtle"
	"google.golang.org/protobuf/proto"
)

var (
	ecdsaSignerKeyVersion   = 0
	ecdsaSignerTypeURL      = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey"
	ed25519SignerKeyVersion = 0
	ed25519SignerTypeURL    = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"
)

// KeyHandleToSigner converts a key handle to the crypto.Signer interface.
// Heavily pulls from Tink's signature and subtle packages.
func KeyHandleToSigner(kh *keyset.Handle) (crypto.Signer, crypto.Hash, error) {
	// extract the key material from the key handle
	ks := insecurecleartextkeyset.KeysetMaterial(kh)

	k := getPrimaryKey(ks)
	if k == nil {
		return nil, 0, errors.New("no enabled key found in keyset")
	}

	switch k.GetTypeUrl() {
	case ecdsaSignerTypeURL:
		// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/ecdsa/signer_key_manager.go#L48
		privKey := new(ecdsapb.EcdsaPrivateKey)
		if err := proto.Unmarshal(k.GetValue(), privKey); err != nil {
			return nil, 0, fmt.Errorf("error unmarshalling ecdsa private key: %w", err)
		}
		if err := validateEcdsaPrivKey(privKey); err != nil {
			return nil, 0, fmt.Errorf("error validating ecdsa private key: %w", err)
		}
		// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/subtle/ecdsa_signer.go#L37
		hashAlg, curve, _ := getECDSAParamNames(privKey.PublicKey.Params)
		p := new(ecdsa.PrivateKey)
		c := subtle.GetCurve(curve)
		if c == nil {
			return nil, 0, errors.New("tink ecdsa signer: invalid curve")
		}
		p.PublicKey.Curve = c
		p.D = new(big.Int).SetBytes(privKey.GetKeyValue())
		p.PublicKey.X, p.PublicKey.Y = c.ScalarBaseMult(privKey.GetKeyValue())
		hash := getHashFunc(hashAlg)
		return p, hash, nil
	case ed25519SignerTypeURL:
		// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/ed25519/signer_key_manager.go#L47
		privKey := new(ed25519pb.Ed25519PrivateKey)
		if err := proto.Unmarshal(k.GetValue(), privKey); err != nil {
			return nil, 0, fmt.Errorf("error unmarshalling ed25519 private key: %w", err)
		}
		if err := validateEd25519PrivKey(privKey); err != nil {
			return nil, 0, fmt.Errorf("error validating ed25519 private key: %w", err)
		}
		// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/subtle/ed25519_signer.go#L27
		p := ed25519.NewKeyFromSeed(privKey.GetKeyValue())
		return p, crypto.SHA512, nil
	default:
		return nil, 0, fmt.Errorf("unsupported key type: %s", k.GetTypeUrl())
	}
}

// getPrimaryKey returns the first enabled key from a keyset.
func getPrimaryKey(ks *tinkpb.Keyset) *tinkpb.KeyData {
	for _, k := range ks.GetKey() {
		if k.GetKeyId() == ks.GetPrimaryKeyId() && k.GetStatus() == tinkpb.KeyStatusType_ENABLED {
			return k.GetKeyData()
		}
	}
	return nil
}

// validateEcdsaPrivKey validates the given ECDSAPrivateKey.
// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/ecdsa/signer_key_manager.go#L151
func validateEcdsaPrivKey(key *ecdsapb.EcdsaPrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, uint32(ecdsaSignerKeyVersion)); err != nil {
		return fmt.Errorf("ecdsa: invalid key version in key: %s", err)
	}
	if err := keyset.ValidateKeyVersion(key.GetPublicKey().GetVersion(), uint32(ecdsaSignerKeyVersion)); err != nil {
		return fmt.Errorf("ecdsa: invalid public version in key: %s", err)
	}
	hash, curve, encoding := getECDSAParamNames(key.PublicKey.Params)
	return signatureSubtle.ValidateECDSAParams(hash, curve, encoding)
}

// getECDSAParamNames returns the string representations of each parameter in
// the given ECDSAParams.
// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/ecdsa/proto.go#L24
func getECDSAParamNames(params *ecdsapb.EcdsaParams) (string, string, string) {
	hashName := commonpb.HashType_name[int32(params.GetHashType())]
	curveName := commonpb.EllipticCurveType_name[int32(params.GetCurve())]
	encodingName := ecdsapb.EcdsaSignatureEncoding_name[int32(params.GetEncoding())]
	return hashName, curveName, encodingName
}

// validateEd25519PrivKey validates the given ED25519PrivateKey.
// https://github.com/tink-crypto/tink-go/blob/0aadc94a816408c4bdf95885b3c9860ecfd55fc0/signature/ed25519/signer_key_manager.go#L157
func validateEd25519PrivKey(key *ed25519pb.Ed25519PrivateKey) error {
	if err := keyset.ValidateKeyVersion(key.Version, uint32(ed25519SignerKeyVersion)); err != nil {
		return fmt.Errorf("ed25519: invalid key: %w", err)
	}
	if len(key.KeyValue) != ed25519.SeedSize {
		return fmt.Errorf("ed25519: invalid key length, got %d", len(key.KeyValue))
	}
	return nil
}

// getHashFunc returns the hash function for a given hash name
func getHashFunc(hash string) crypto.Hash {
	switch hash {
	case "SHA1":
		return crypto.SHA1
	case "SHA224":
		return crypto.SHA224
	case "SHA256":
		return crypto.SHA256
	case "SHA384":
		return crypto.SHA384
	case "SHA512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}
