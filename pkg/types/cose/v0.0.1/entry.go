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

package cose

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/cose"
	gocose "github.com/veraison/go-cose"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := cose.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	CoseObj models.CoseV001Schema
	keyObj  pki.PublicKey
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	// We add the key, the hash of the overall cose envelope, and the hash of the payload itself as keys.
	keyObj, err := x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return nil, err
	}

	// 1. Key
	key, err := keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}
	result = append(result, keyObj.EmailAddresses()...)

	// 2. Overall envelope
	result = append(result, formatKey(*v.CoseObj.Message))

	// 3. Payload
	if v.CoseObj.Data.Content != nil {
		result = append(result, formatKey(*v.CoseObj.Data.Content))
	}

	return result, nil
}

func formatKey(b []byte) string {
	h := sha256.Sum256(b)
	hash := hex.EncodeToString(h[:])
	return strings.ToLower(fmt.Sprintf("%s:%s", models.CoseV001SchemaDataHashAlgorithmSha256, hash))
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	it, ok := pe.(*models.Cose)
	if !ok {
		return errors.New("cannot unmarshal non Cose v0.0.1 type")
	}

	var err error
	if err := types.DecodeEntry(it.Spec, &v.CoseObj); err != nil {
		return err
	}

	// field validation
	if err := v.CoseObj.Validate(strfmt.Default); err != nil {
		return err
	}

	v.keyObj, err = x509.NewPublicKey(bytes.NewReader(*v.CoseObj.PublicKey))
	if err != nil {
		return err
	}

	// Check and make sure the hash value is correct.
	h := sha256.Sum256(*v.CoseObj.Message)
	computedSha := hex.EncodeToString(h[:])

	if v.CoseObj.Data.Hash != nil {
		if computedSha != *v.CoseObj.Data.Hash.Value {
			return errors.New("hash mismatch")
		}
	} else {
		v.CoseObj.Data.Hash = &models.CoseV001SchemaDataHash{
			Algorithm: swag.String(models.CoseV001SchemaDataHashAlgorithmSha256),
			Value:     &computedSha,
		}
	}
	return v.validate()
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if v.keyObj == nil {
		return nil, errors.New("cannot canonicalze empty key")
	}
	pk, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	pkb := strfmt.Base64(pk)

	h := sha256.Sum256([]byte(v.CoseObj.Data.Content.String()))

	canonicalEntry := models.CoseV001Schema{
		PublicKey: &pkb,
		Data: &models.CoseV001SchemaData{
			Hash: &models.CoseV001SchemaDataHash{
				Algorithm: swag.String(models.CoseV001SchemaDataHashAlgorithmSha256),
				Value:     swag.String(hex.EncodeToString(h[:])),
			},
		},
	}

	itObj := models.Cose{}
	itObj.APIVersion = swag.String(APIVERSION)
	itObj.Spec = &canonicalEntry

	return json.Marshal(&itObj)
}

// validate performs cross-field validation for fields in object
func (v *V001Entry) validate() error {

	// This also gets called in the CLI, where we won't have this data
	if v.CoseObj.Message == nil {
		return nil
	}

	pk := v.keyObj.(*x509.PublicKey)
	cryptoPub := pk.CryptoPubKey()

	var alg *gocose.Algorithm
	switch t := cryptoPub.(type) {
	case *rsa.PublicKey:
		alg = gocose.PS256
	case *ecdsa.PublicKey:
		alg = gocose.ES256
	default:
		return fmt.Errorf("unsupported algorithm type %T", t)
	}

	bv := gocose.Verifier{
		PublicKey: cryptoPub,
		Alg:       alg,
	}

	msg := gocose.NewSign1Message()
	if err := msg.UnmarshalCBOR(*v.CoseObj.Message); err != nil {
		return err
	}

	return msg.Verify(*v.CoseObj.Data.Content, bv)
}

func (v *V001Entry) Attestation() []byte {
	return nil
}

func (v V001Entry) CreateFromArtifactProperties(_ context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Cose{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			return nil, errors.New("cose envelopes cannot be fetched over HTTP(S)")
		}
		artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, err
		}
	}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("public key must be provided to verify signature")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	kb := strfmt.Base64(publicKeyBytes)
	ab := strfmt.Base64(artifactBytes)

	re := V001Entry{
		CoseObj: models.CoseV001Schema{
			Data: &models.CoseV001SchemaData{
				Content: &ab,
			},
			PublicKey: &kb,
		},
	}

	returnVal.Spec = re.CoseObj
	returnVal.APIVersion = swag.String(re.APIVersion())

	return &returnVal, nil
}
