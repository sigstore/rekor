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

package alpine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"golang.org/x/sync/errgroup"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/x509"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/alpine"
	"github.com/sigstore/rekor/pkg/util"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := alpine.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	AlpineModel             models.AlpineV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
	apkObj                  *alpine.Package
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	if v.hasExternalEntities() {
		if err := v.fetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	key, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}

	result = append(result, v.keyObj.EmailAddresses()...)

	if v.AlpineModel.Package.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.AlpineModel.Package.Hash.Algorithm, *v.AlpineModel.Package.Hash.Value))
		result = append(result, hashKey)
	}

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	apk, ok := pe.(*models.Alpine)
	if !ok {
		return errors.New("cannot unmarshal non Alpine v0.0.1 type")
	}

	if err := types.DecodeEntry(apk.Spec, &v.AlpineModel); err != nil {
		return err
	}

	// field validation
	if err := v.AlpineModel.Validate(strfmt.Default); err != nil {
		return err
	}

	return v.validate()
}

func (v V001Entry) hasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.AlpineModel.Package != nil && v.AlpineModel.Package.URL.String() != "" {
		return true
	}
	if v.AlpineModel.PublicKey != nil && v.AlpineModel.PublicKey.URL.String() != "" {
		return true
	}
	return false
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) error {
	if v.fetchedExternalEntities {
		return nil
	}

	if err := v.validate(); err != nil {
		return types.ValidationError(err)
	}

	artifactFactory, err := pki.NewArtifactFactory(pki.X509)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	apkR, apkW := io.Pipe()
	defer hashR.Close()
	defer apkR.Close()

	closePipesOnError := types.PipeCloser(hashR, hashW, apkR, apkW)

	oldSHA := ""
	if v.AlpineModel.Package.Hash != nil && v.AlpineModel.Package.Hash.Value != nil {
		oldSHA = swag.StringValue(v.AlpineModel.Package.Hash.Value)
	}

	g.Go(func() error {
		defer hashW.Close()
		defer apkW.Close()

		dataReadCloser, err := util.FileOrURLReadCloser(ctx, v.AlpineModel.Package.URL.String(), v.AlpineModel.Package.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer dataReadCloser.Close()

		/* #nosec G110 */
		if _, err := io.Copy(io.MultiWriter(hashW, apkW), dataReadCloser); err != nil {
			return closePipesOnError(err)
		}
		return nil
	})

	hashResult := make(chan string)

	g.Go(func() error {
		defer close(hashResult)
		hasher := sha256.New()

		if _, err := io.Copy(hasher, hashR); err != nil {
			return closePipesOnError(err)
		}

		computedSHA := hex.EncodeToString(hasher.Sum(nil))
		if oldSHA != "" && computedSHA != oldSHA {
			return closePipesOnError(types.ValidationError(fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA)))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case hashResult <- computedSHA:
			return nil
		}
	})

	keyResult := make(chan *x509.PublicKey)

	g.Go(func() error {
		defer close(keyResult)
		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.AlpineModel.PublicKey.URL.String(),
			v.AlpineModel.PublicKey.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer keyReadCloser.Close()

		v.keyObj, err = artifactFactory.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case keyResult <- v.keyObj.(*x509.PublicKey):
			return nil
		}
	})

	g.Go(func() error {
		apk := alpine.Package{}
		if err := apk.Unmarshal(apkR); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		key := <-keyResult
		if key == nil {
			return closePipesOnError(errors.New("error processing public key"))
		}

		if err := apk.VerifySignature(key.CryptoPubKey()); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		v.apkObj = &apk

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	computedSHA := <-hashResult

	if err := g.Wait(); err != nil {
		return err
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.AlpineModel.Package.Hash = &models.AlpineV001SchemaPackageHash{}
		v.AlpineModel.Package.Hash.Algorithm = swag.String(models.AlpineV001SchemaPackageHashAlgorithmSha256)
		v.AlpineModel.Package.Hash.Value = swag.String(computedSHA)
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.fetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.AlpineV001Schema{}

	var err error

	// need to canonicalize key content
	canonicalEntry.PublicKey = &models.AlpineV001SchemaPublicKey{}
	canonicalEntry.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Package = &models.AlpineV001SchemaPackage{}
	canonicalEntry.Package.Hash = &models.AlpineV001SchemaPackageHash{}
	canonicalEntry.Package.Hash.Algorithm = v.AlpineModel.Package.Hash.Algorithm
	canonicalEntry.Package.Hash.Value = v.AlpineModel.Package.Hash.Value
	// data content is not set deliberately

	// set .PKGINFO headers
	canonicalEntry.Package.Pkginfo = v.apkObj.Pkginfo

	// wrap in valid object with kind and apiVersion set
	apk := models.Alpine{}
	apk.APIVersion = swag.String(APIVERSION)
	apk.Spec = &canonicalEntry

	return json.Marshal(&apk)
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() error {
	key := v.AlpineModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 && key.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
	}

	pkg := v.AlpineModel.Package
	if pkg == nil {
		return errors.New("missing package")
	}

	hash := pkg.Hash
	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
	} else if len(pkg.Content) == 0 && pkg.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for package")
	}

	return nil
}

func (v V001Entry) Attestation() (string, []byte) {
	return "", nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Alpine{}
	re := V001Entry{}

	// we will need artifact, public-key, signature
	re.AlpineModel = models.AlpineV001Schema{}
	re.AlpineModel.Package = &models.AlpineV001SchemaPackage{}

	var err error
	artifactBytes := props.ArtifactBytes
	if artifactBytes == nil {
		if props.ArtifactPath.IsAbs() {
			re.AlpineModel.Package.URL = strfmt.URI(props.ArtifactPath.String())
			if props.ArtifactHash != "" {
				re.AlpineModel.Package.Hash = &models.AlpineV001SchemaPackageHash{
					Algorithm: swag.String(models.AlpineV001SchemaPackageHashAlgorithmSha256),
					Value:     swag.String(props.ArtifactHash),
				}
			}
		} else {
			artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading artifact file: %w", err)
			}
			re.AlpineModel.Package.Content = strfmt.Base64(artifactBytes)
		}
	} else {
		re.AlpineModel.Package.Content = strfmt.Base64(artifactBytes)
	}

	re.AlpineModel.PublicKey = &models.AlpineV001SchemaPublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath.IsAbs() {
			re.AlpineModel.PublicKey.URL = strfmt.URI(props.PublicKeyPath.String())
		} else {
			publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading public key file: %w", err)
			}
			re.AlpineModel.PublicKey.Content = strfmt.Base64(publicKeyBytes)
		}
	} else {
		re.AlpineModel.PublicKey.Content = strfmt.Base64(publicKeyBytes)
	}

	if err := re.validate(); err != nil {
		return nil, err
	}

	if re.hasExternalEntities() {
		if err := re.fetchExternalEntities(ctx); err != nil {
			return nil, fmt.Errorf("error retrieving external entities: %v", err)
		}
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.AlpineModel

	return &returnVal, nil
}
