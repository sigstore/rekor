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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
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
	AlpineModel models.AlpineV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	keyObj, err := x509.NewPublicKey(bytes.NewReader(*v.AlpineModel.PublicKey.Content))
	if err != nil {
		return nil, err
	}
	key, err := keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(key)
	result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))

	result = append(result, keyObj.Subjects()...)

	if v.AlpineModel.Package.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.AlpineModel.Package.Hash.Algorithm, *v.AlpineModel.Package.Hash.Value))
		result = append(result, hashKey)
	}

	return result, nil
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

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (*x509.PublicKey, *alpine.Package, error) {
	if err := v.validate(); err != nil {
		return nil, nil, types.ValidationError(err)
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

		dataReadCloser := bytes.NewReader(v.AlpineModel.Package.Content)

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
		keyReadCloser := bytes.NewReader(*v.AlpineModel.PublicKey.Content)

		keyObj, err := x509.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case keyResult <- keyObj:
			return nil
		}
	})

	var apkObj *alpine.Package
	var key *x509.PublicKey

	g.Go(func() error {
		apk := alpine.Package{}
		if err := apk.Unmarshal(apkR); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		key = <-keyResult
		if key == nil {
			return closePipesOnError(errors.New("error processing public key"))
		}

		if err := apk.VerifySignature(key.CryptoPubKey()); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		apkObj = &apk

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	computedSHA := <-hashResult

	if err := g.Wait(); err != nil {
		return nil, nil, err
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.AlpineModel.Package.Hash = &models.AlpineV001SchemaPackageHash{}
		v.AlpineModel.Package.Hash.Algorithm = swag.String(models.AlpineV001SchemaPackageHashAlgorithmSha256)
		v.AlpineModel.Package.Hash.Value = swag.String(computedSHA)
	}

	return key, apkObj, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	key, apkObj, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.AlpineV001Schema{}

	var content []byte
	// need to canonicalize key content
	canonicalEntry.PublicKey = &models.AlpineV001SchemaPublicKey{}
	content, err = key.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.PublicKey.Content = (*strfmt.Base64)(&content)

	canonicalEntry.Package = &models.AlpineV001SchemaPackage{}
	canonicalEntry.Package.Hash = &models.AlpineV001SchemaPackageHash{}
	canonicalEntry.Package.Hash.Algorithm = v.AlpineModel.Package.Hash.Algorithm
	canonicalEntry.Package.Hash.Value = v.AlpineModel.Package.Hash.Value
	// data content is not set deliberately

	// set .PKGINFO headers
	canonicalEntry.Package.Pkginfo = apkObj.Pkginfo

	// wrap in valid object with kind and apiVersion set
	apk := models.Alpine{}
	apk.APIVersion = swag.String(APIVERSION)
	apk.Spec = &canonicalEntry

	v.AlpineModel = canonicalEntry

	return json.Marshal(&apk)
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() error {
	key := v.AlpineModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if key.Content == nil || len(*key.Content) == 0 {
		return errors.New("'content' must be specified for publicKey")
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
	} else if len(pkg.Content) == 0 {
		return errors.New("'content' must be specified for package")
	}

	return nil
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
		var artifactReader io.ReadCloser
		if props.ArtifactPath == nil {
			return nil, errors.New("path to artifact file must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			artifactReader, err = util.FileOrURLReadCloser(ctx, props.ArtifactPath.String(), nil)
			if err != nil {
				return nil, fmt.Errorf("error reading artifact file: %w", err)
			}
		} else {
			artifactReader, err = os.Open(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error opening artifact file: %w", err)
			}
		}
		artifactBytes, err = io.ReadAll(artifactReader)
		if err != nil {
			return nil, fmt.Errorf("error reading artifact file: %w", err)
		}
	}
	re.AlpineModel.Package.Content = strfmt.Base64(artifactBytes)

	re.AlpineModel.PublicKey = &models.AlpineV001SchemaPublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if len(publicKeyBytes) == 0 {
		if len(props.PublicKeyPaths) != 1 {
			return nil, errors.New("only one public key must be provided")
		}
		keyBytes, err := os.ReadFile(filepath.Clean(props.PublicKeyPaths[0].Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
		publicKeyBytes = append(publicKeyBytes, keyBytes)
	} else if len(publicKeyBytes) != 1 {
		return nil, errors.New("only one public key must be provided")
	}

	re.AlpineModel.PublicKey.Content = (*strfmt.Base64)(&publicKeyBytes[0])

	if err := re.validate(); err != nil {
		return nil, err
	}

	if _, _, err := re.fetchExternalEntities(ctx); err != nil {
		return nil, fmt.Errorf("error retrieving external entities: %w", err)
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.AlpineModel

	return &returnVal, nil
}

func (v V001Entry) Verifiers() ([]pki.PublicKey, error) {
	if v.AlpineModel.PublicKey == nil || v.AlpineModel.PublicKey.Content == nil {
		return nil, errors.New("alpine v0.0.1 entry not initialized")
	}
	key, err := x509.NewPublicKey(bytes.NewReader(*v.AlpineModel.PublicKey.Content))
	if err != nil {
		return nil, err
	}
	return []pki.PublicKey{key}, nil
}

func (v V001Entry) ArtifactHash() (string, error) {
	if v.AlpineModel.Package == nil || v.AlpineModel.Package.Hash == nil || v.AlpineModel.Package.Hash.Value == nil || v.AlpineModel.Package.Hash.Algorithm == nil {
		return "", errors.New("alpine v0.0.1 entry not initialized")
	}
	return strings.ToLower(fmt.Sprintf("%s:%s", *v.AlpineModel.Package.Hash.Algorithm, *v.AlpineModel.Package.Hash.Value)), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.AlpineModel.Package == nil {
		return false, errors.New("missing package entry")
	}
	if len(v.AlpineModel.Package.Content) == 0 {
		return false, errors.New("missing package content")
	}
	if v.AlpineModel.PublicKey == nil {
		return false, errors.New("missing public key")
	}
	if v.AlpineModel.PublicKey.Content == nil || len(*v.AlpineModel.PublicKey.Content) == 0 {
		return false, errors.New("missing public key content")
	}
	return true, nil
}
