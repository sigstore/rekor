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

package hashedrekord

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := hashedrekord.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	HashedRekordObj models.HashedrekordV001Schema
	keyObj          pki.PublicKey
	sigObj          pki.Signature
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	key, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}

	result = append(result, v.keyObj.EmailAddresses()...)

	if v.HashedRekordObj.Data.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.HashedRekordObj.Data.Hash.Algorithm, *v.HashedRekordObj.Data.Hash.Value))
		result = append(result, hashKey)
	}

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	rekord, ok := pe.(*models.Hashedrekord)
	if !ok {
		return errors.New("cannot unmarshal non Rekord v0.0.1 type")
	}

	if err := types.DecodeEntry(rekord.Spec, &v.HashedRekordObj); err != nil {
		return err
	}

	// field validation
	if err := v.HashedRekordObj.Validate(strfmt.Default); err != nil {
		return err
	}

	// cross field validation
	return v.validate()
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, types.ValidationError(err)
	}

	if v.sigObj == nil {
		return nil, errors.New("signature object not initialized before canonicalization")
	}

	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.HashedrekordV001Schema{}

	// need to canonicalize signature & key content
	canonicalEntry.Signature = &models.HashedrekordV001SchemaSignature{}
	var err error
	canonicalEntry.Signature.Content, err = v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	// key URL (if known) is not set deliberately
	canonicalEntry.Signature.PublicKey = &models.HashedrekordV001SchemaSignaturePublicKey{}
	canonicalEntry.Signature.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Data = &models.HashedrekordV001SchemaData{}
	canonicalEntry.Data.Hash = v.HashedRekordObj.Data.Hash
	// data content is not set deliberately

	// wrap in valid object with kind and apiVersion set
	rekordObj := models.Hashedrekord{}
	rekordObj.APIVersion = swag.String(APIVERSION)
	rekordObj.Spec = &canonicalEntry

	return json.Marshal(&rekordObj)
}

// validate performs cross-field validation for fields in object
func (v *V001Entry) validate() error {
	sig := v.HashedRekordObj.Signature
	if sig == nil {
		return types.ValidationError(errors.New("missing signature"))
	}
	// Hashed rekord type only works for x509 signature types
	artifactFactory, err := pki.NewArtifactFactory(pki.X509)
	if err != nil {
		return types.ValidationError(err)
	}
	v.sigObj, err = artifactFactory.NewSignature(bytes.NewReader(sig.Content))
	if err != nil {
		return types.ValidationError(err)
	}

	key := sig.PublicKey
	if key == nil {
		return types.ValidationError(errors.New("missing public key"))
	}
	v.keyObj, err = artifactFactory.NewPublicKey(bytes.NewReader(key.Content))
	if err != nil {
		return types.ValidationError(err)
	}

	data := v.HashedRekordObj.Data
	if data == nil {
		return types.ValidationError(errors.New("missing data"))
	}

	hash := data.Hash
	if hash == nil {
		return types.ValidationError(errors.New("missing hash"))
	}
	if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
		return types.ValidationError(errors.New("invalid value for hash"))
	}

	decoded, err := hex.DecodeString(*hash.Value)
	if err != nil {
		return err
	}
	if err = v.sigObj.Verify(nil, v.keyObj, options.WithDigest(decoded)); err != nil {
		return types.ValidationError(errors.Wrap(err, "verifying signature"))
	}

	return nil
}

func (v V001Entry) Attestation() (string, []byte) {
	return "", nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Hashedrekord{}
	re := V001Entry{}

	// we will need artifact, public-key, signature
	re.HashedRekordObj.Data = &models.HashedrekordV001SchemaData{}

	var err error

	re.HashedRekordObj.Signature = &models.HashedrekordV001SchemaSignature{}
	sigBytes := props.SignatureBytes
	if sigBytes == nil {
		if props.SignaturePath == nil {
			return nil, errors.New("a detached signature must be provided")
		}
		sigBytes, err = ioutil.ReadFile(filepath.Clean(props.SignaturePath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading signature file: %w", err)
		}
	}
	re.HashedRekordObj.Signature.Content = strfmt.Base64(sigBytes)

	re.HashedRekordObj.Signature.PublicKey = &models.HashedrekordV001SchemaSignaturePublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("public key must be provided to verify detached signature")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	re.HashedRekordObj.Signature.PublicKey.Content = strfmt.Base64(publicKeyBytes)

	re.HashedRekordObj.Data.Hash = &models.HashedrekordV001SchemaDataHash{
		Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
		Value:     swag.String(props.ArtifactHash),
	}

	if err := re.validate(); err != nil {
		return nil, err
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.HashedRekordObj

	return &returnVal, nil
}
