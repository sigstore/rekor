//
// Copyright 2022 The Sigstore Authors.
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

/*
Should be able to reconstruct the entry with the sig location and
the container digest?

*/

package container

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

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/container"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := container.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	ContainerObj models.ContainerV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	keyObj, err := x509.NewPublicKey(bytes.NewReader(v.ContainerObj.Signature.PublicKey.Content))
	if err != nil {
		return nil, err
	}

	key, err := keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}

	result = append(result, keyObj.EmailAddresses()...)

	// This is the hash of the signed payload.
	hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.ContainerObj.Data.Hash.Algorithm, *v.ContainerObj.Data.Hash.Value))
	result = append(result, hashKey)

	// This is the container digest that is signed.
	if v.ContainerObj.Data.Content != nil {
		// Marshal and unmarshal into a payload.Cosign.
		b, err := json.Marshal(v.ContainerObj.Data.Content)
		if err != nil {
			log.Logger.Error(err)
		} else {
			img := &payload.Cosign{}
			if err := json.Unmarshal(b, img); err == nil {
				// This is the hash of the container signed.
				result = append(result, img.Image.DigestStr())
				// This is the docker reference.
				result = append(result, img.Image.Repository.Name())
				fmt.Println(img.Image.DigestStr())
				fmt.Println(img.Image.Repository.Name())
			}
		}
	}

	return result, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	container, ok := pe.(*models.Container)
	if !ok {
		return errors.New("cannot unmarshal non container v0.0.1 type")
	}

	if err := types.DecodeEntry(container.Spec, &v.ContainerObj); err != nil {
		return err
	}

	// field validation
	if err := v.ContainerObj.Validate(strfmt.Default); err != nil {
		return err
	}

	// cross field validation
	_, _, err := v.validate()
	return err

}

func (v *V001Entry) fetchExternalEntities(artifactBytes []byte) error {
	sig := v.ContainerObj.Signature
	sigObj, err := x509.NewSignature(bytes.NewReader(sig.Content))
	if err != nil {
		return types.ValidationError(err)
	}

	key := sig.PublicKey
	if key == nil {
		return types.ValidationError(errors.New("missing public key"))
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(key.Content))
	if err != nil {
		return types.ValidationError(err)
	}

	if err := sigObj.Verify(bytes.NewReader(artifactBytes), keyObj); err != nil {
		return types.ValidationError(errors.Wrap(err, "verifying signature"))
	}

	// if we get here, all goroutines succeeded without error, populate content and hash
	img := &payload.Cosign{}
	if err := json.Unmarshal(artifactBytes, img); err != nil {
		return err
	}
	v.ContainerObj.Data.Content = img
	v.ContainerObj.Data.Hash = &models.ContainerV001SchemaDataHash{}
	v.ContainerObj.Data.Hash.Algorithm = swag.String(models.ContainerV001SchemaDataHashAlgorithmSha256)
	h := sha256.Sum256(artifactBytes)
	v.ContainerObj.Data.Hash.Value = swag.String(hex.EncodeToString(h[:]))

	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	// At this point SHA should have already been populated.
	keyObj, sigObj, err := v.validate()
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.ContainerV001Schema{}

	// need to canonicalize signature & key content
	canonicalEntry.Signature = &models.ContainerV001SchemaSignature{}
	// signature URL (if known) is not set deliberately
	canonicalEntry.Signature.Content, err = sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	// key URL (if known) is not set deliberately
	canonicalEntry.Signature.PublicKey = &models.ContainerV001SchemaSignaturePublicKey{}
	canonicalEntry.Signature.PublicKey.Content, err = keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	// both content (for image reference) and hash (for verification) are specified
	canonicalEntry.Data = v.ContainerObj.Data

	// wrap in valid object with kind and apiVersion set
	containerObj := models.Container{}
	containerObj.APIVersion = swag.String(APIVERSION)
	containerObj.Spec = &canonicalEntry

	v.ContainerObj = canonicalEntry

	bytes, err := json.Marshal(&containerObj)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() (pki.PublicKey, pki.Signature, error) {
	sig := v.ContainerObj.Signature
	if v.ContainerObj.Signature == nil {
		return nil, nil, types.ValidationError(errors.New("missing signature"))
	}
	if len(sig.Content) == 0 {
		return nil, nil, errors.New("'content' must be specified for signature")
	}
	sigObj, err := x509.NewSignature(bytes.NewReader(sig.Content))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	key := sig.PublicKey
	if key == nil {
		return nil, nil, types.ValidationError(errors.New("missing public key"))
	}
	if len(key.Content) == 0 {
		return nil, nil, errors.New("'content'  must be specified for publicKey")
	}
	keyObj, err := x509.NewPublicKey(bytes.NewReader(key.Content))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	data := v.ContainerObj.Data
	if data == nil {
		return nil, nil, errors.New("missing data")
	}
	if data.Content == nil {
		return nil, nil, errors.New("'content' must be specified for data")
	}

	hash := data.Hash
	if hash == nil {
		return nil, nil, errors.New("'hash' must be specified for data")
	}
	decoded, err := hex.DecodeString(*hash.Value)
	if err != nil {
		return nil, nil, err
	}
	if err := sigObj.Verify(nil, keyObj, options.WithDigest(decoded)); err != nil {
		return nil, nil, types.ValidationError(errors.Wrap(err, "verifying signature"))
	}

	return keyObj, sigObj, nil
}

func (v V001Entry) Attestation() []byte {
	return nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Container{}
	re := V001Entry{}

	// we will need artifact, public-key, signature
	re.ContainerObj.Data = &models.ContainerV001SchemaData{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("filepath to artifact must be specified")
		}
		artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading artifact file: %w", err)
		}
	}

	sigBytes := props.SignatureBytes
	if sigBytes == nil {
		if props.SignaturePath == nil {
			return nil, errors.New("a detached signature must be provided")
		}
		if props.SignaturePath.IsAbs() {
			return nil, errors.New("must provide valid signature file")
		}
		sigBytes, err = ioutil.ReadFile(filepath.Clean(props.SignaturePath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading signature file: %w", err)
		}
	}

	re.ContainerObj.Signature = &models.ContainerV001SchemaSignature{}
	re.ContainerObj.Signature.Content = strfmt.Base64(sigBytes)
	re.ContainerObj.Signature.PublicKey = &models.ContainerV001SchemaSignaturePublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("public key must be provided to verify detached signature")
		}
		if props.PublicKeyPath.IsAbs() {
			return nil, errors.New("must provide valid public key file")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	re.ContainerObj.Signature.PublicKey.Content = strfmt.Base64(publicKeyBytes)

	// validates and sets the data hash
	if err := re.fetchExternalEntities(bytes.TrimSpace(artifactBytes)); err != nil {
		return nil, fmt.Errorf("error validating entry: %w", err)
	}

	if _, _, err := re.validate(); err != nil {
		return nil, err
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.ContainerObj

	return &returnVal, nil
}
