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
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature/payload"

	"github.com/asaskevich/govalidator"
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

	// TODO: Do we always expect x509 keys signing containers?
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
	if v.ContainerObj.Data.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.ContainerObj.Data.Hash.Algorithm, *v.ContainerObj.Data.Hash.Value))
		result = append(result, hashKey)
	}

	// This is the container digest that is signed.
	if v.ContainerObj.Data.Content != nil {
		// Marshal and unmarshal into a payload.Cosign.
		b, err := json.Marshal(v.ContainerObj.Data.Content)
		if err != nil {
			log.Logger.Error(err)
		} else {
			img := &payload.Cosign{}
			if err := json.Unmarshal(b, img); err == nil {
				result = append(result, img.Image.DigestStr())
			}
		}
		// TODO: Should we include the image reference as well?
		// TODO: What to do about optional annotations?
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
	return v.validate()

}

func (v *V001Entry) hasExternalEntities() bool {
	if v.ContainerObj.Data != nil && v.ContainerObj.Data.URL.String() != "" {
		return true
	}
	// TODO: Allow signature/public key URLs or no?
	return false
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (pki.PublicKey, pki.Signature, error) {
	oldSHA := ""
	if v.ContainerObj.Data.Hash != nil && v.ContainerObj.Data.Hash.Value != nil {
		oldSHA = swag.StringValue(v.ContainerObj.Data.Hash.Value)
	}

	var contentBytes []byte
	if v.ContainerObj.Data.Content != nil {
		var err error
		contentBytes, err = json.Marshal(v.ContainerObj.Data.Content)
		if err != nil {
			return nil, nil, err
		}
	}
	dataReadCloser, err := util.FileOrURLReadCloser(ctx, v.ContainerObj.Data.URL.String(), contentBytes)
	if err != nil {
		return nil, nil, err
	}
	defer dataReadCloser.Close()

	hasher := sha256.New()
	b := &bytes.Buffer{}
	c := &bytes.Buffer{}

	_, err = io.Copy(io.MultiWriter(hasher, b, c), dataReadCloser)
	if err != nil {
		return nil, nil, err
	}

	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if oldSHA != "" && computedSHA != oldSHA {
		return nil, nil, types.ValidationError(fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA))
	}

	af, err := pki.NewArtifactFactory(pki.Format(v.ContainerObj.Signature.Format))
	if err != nil {
		return nil, nil, err
	}

	sig := v.ContainerObj.Signature
	sigObj, err := af.NewSignature(bytes.NewReader(sig.Content))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	key := sig.PublicKey
	if key == nil {
		return nil, nil, types.ValidationError(errors.New("missing public key"))
	}
	keyObj, err := af.NewPublicKey(bytes.NewReader(key.Content))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	if err := sigObj.Verify(b, keyObj); err != nil {
		return nil, nil, types.ValidationError(errors.Wrap(err, "verifying signature"))
	}

	// if we get here, all goroutines succeeded without error
	// TODO: Rekor shouldn't store the Data.Content, or should it?
	if oldSHA == "" {
		v.ContainerObj.Data.Hash = &models.ContainerV001SchemaDataHash{}
		v.ContainerObj.Data.Hash.Algorithm = swag.String(models.ContainerV001SchemaDataHashAlgorithmSha256)
		v.ContainerObj.Data.Hash.Value = swag.String(computedSHA)
	}

	return keyObj, sigObj, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	keyObj, sigObj, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.ContainerV001Schema{}

	// need to canonicalize signature & key content
	canonicalEntry.Signature = &models.ContainerV001SchemaSignature{}
	// signature URL (if known) is not set deliberately
	canonicalEntry.Signature.Format = v.ContainerObj.Signature.Format

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

	canonicalEntry.Data = &models.ContainerV001SchemaData{}
	canonicalEntry.Data.Hash = v.ContainerObj.Data.Hash
	// data content is set if present so that the image reference can be hashed
	canonicalEntry.Data.Content = v.ContainerObj.Data.Content

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
func (v V001Entry) validate() error {
	sig := v.ContainerObj.Signature
	if v.ContainerObj.Signature == nil {
		return errors.New("missing signature")
	}
	if len(sig.Content) == 0 {
		return errors.New("'content' must be specified for signature")
	}

	key := sig.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 {
		return errors.New("'content'  must be specified for publicKey")
	}

	data := v.ContainerObj.Data
	if data == nil {
		return errors.New("missing data")
	}

	hash := data.Hash
	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
	} else if data.Content == nil && data.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for data")
	}

	return nil
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
			return nil, errors.New("path to artifact (file or URL) must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			re.ContainerObj.Data.URL = strfmt.URI(props.ArtifactPath.String())
			if props.ArtifactHash != "" {
				re.ContainerObj.Data.Hash = &models.ContainerV001SchemaDataHash{
					Algorithm: swag.String(models.ContainerV001SchemaDataHashAlgorithmSha256),
					Value:     swag.String(props.ArtifactHash),
				}
			}
		} else {
			artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading artifact file: %w", err)
			}
		}
	}
	if artifactBytes != nil {
		img := &payload.Cosign{}
		if err := json.Unmarshal(artifactBytes, img); err != nil {
			return nil, err
		}
		re.ContainerObj.Data.Content = img
	}

	re.ContainerObj.Signature = &models.ContainerV001SchemaSignature{}
	switch props.PKIFormat {
	case "pgp":
		re.ContainerObj.Signature.Format = models.ContainerV001SchemaSignatureFormatPgp
	case "minisign":
		re.ContainerObj.Signature.Format = models.ContainerV001SchemaSignatureFormatMinisign
	case "x509":
		re.ContainerObj.Signature.Format = models.ContainerV001SchemaSignatureFormatX509
	case "ssh":
		re.ContainerObj.Signature.Format = models.ContainerV001SchemaSignatureFormatSSH
	}
	sigBytes := props.SignatureBytes
	if sigBytes == nil {
		if props.SignaturePath == nil {
			return nil, errors.New("a detached signature must be provided")
		}
		if props.SignaturePath.IsAbs() {
			// TODO probably allow URLs
			return nil, errors.New("must provide valid signature file")
		}
		sigBytes, err = ioutil.ReadFile(filepath.Clean(props.SignaturePath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading signature file: %w", err)
		}
	}
	re.ContainerObj.Signature.Content = strfmt.Base64(sigBytes)

	re.ContainerObj.Signature.PublicKey = &models.ContainerV001SchemaSignaturePublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("public key must be provided to verify detached signature")
		}
		if props.PublicKeyPath.IsAbs() {
			// TODO probably allow URLs
			return nil, errors.New("must provide valid public key file")
		}
		publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
	}
	re.ContainerObj.Signature.PublicKey.Content = strfmt.Base64(publicKeyBytes)

	if err := re.validate(); err != nil {
		return nil, err
	}

	if re.hasExternalEntities() {
		if _, _, err := re.fetchExternalEntities(ctx); err != nil {
			return nil, fmt.Errorf("error retrieving external entities: %v", err)
		}
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.ContainerObj

	return &returnVal, nil
}
