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

package rpm

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
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	rpmutils "github.com/cavaliercoder/go-rpm"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"golang.org/x/sync/errgroup"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/rpm"
	"github.com/sigstore/rekor/pkg/util"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := rpm.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	RPMModel models.RpmV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	keyObj, err := pgp.NewPublicKey(bytes.NewReader(*v.RPMModel.PublicKey.Content))
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

	if v.RPMModel.Package.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.RPMModel.Package.Hash.Algorithm, *v.RPMModel.Package.Hash.Value))
		result = append(result, hashKey)
	}

	return result, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	rpm, ok := pe.(*models.Rpm)
	if !ok {
		return errors.New("cannot unmarshal non RPM v0.0.1 type")
	}

	if err := types.DecodeEntry(rpm.Spec, &v.RPMModel); err != nil {
		return err
	}

	// field validation
	if err := v.RPMModel.Validate(strfmt.Default); err != nil {
		return err
	}

	return v.validate()
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (*pgp.PublicKey, *rpmutils.PackageFile, error) {

	if err := v.validate(); err != nil {
		return nil, nil, types.ValidationError(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	sigR, sigW := io.Pipe()
	rpmR, rpmW := io.Pipe()
	defer hashR.Close()
	defer sigR.Close()
	defer rpmR.Close()

	closePipesOnError := types.PipeCloser(hashR, hashW, sigR, sigW, rpmR, rpmW)

	oldSHA := ""
	if v.RPMModel.Package.Hash != nil && v.RPMModel.Package.Hash.Value != nil {
		oldSHA = swag.StringValue(v.RPMModel.Package.Hash.Value)
	}

	g.Go(func() error {
		defer hashW.Close()
		defer sigW.Close()
		defer rpmW.Close()

		dataReadCloser := bytes.NewReader(v.RPMModel.Package.Content)

		/* #nosec G110 */
		if _, err := io.Copy(io.MultiWriter(hashW, sigW, rpmW), dataReadCloser); err != nil {
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

	var keyObj *pgp.PublicKey
	g.Go(func() error {
		keyReadCloser := bytes.NewReader(*v.RPMModel.PublicKey.Content)

		var err error
		keyObj, err = pgp.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		keyring, err := keyObj.KeyRing()
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		if _, err := rpmutils.GPGCheck(sigR, keyring); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	var rpmObj *rpmutils.PackageFile
	g.Go(func() error {

		var err error
		rpmObj, err = rpmutils.ReadPackageFile(rpmR)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}
		// ReadPackageFile does not drain the entire reader so we need to discard the rest
		if _, err = io.Copy(io.Discard, rpmR); err != nil {
			return closePipesOnError(err)
		}

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
		v.RPMModel.Package.Hash = &models.RpmV001SchemaPackageHash{}
		v.RPMModel.Package.Hash.Algorithm = swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256)
		v.RPMModel.Package.Hash.Value = swag.String(computedSHA)
	}

	return keyObj, rpmObj, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	keyObj, rpmObj, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.RpmV001Schema{}

	// need to canonicalize key content

	var pubKeyContent []byte
	canonicalEntry.PublicKey = &models.RpmV001SchemaPublicKey{}
	pubKeyContent, err = keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.PublicKey.Content = (*strfmt.Base64)(&pubKeyContent)

	canonicalEntry.Package = &models.RpmV001SchemaPackage{}
	canonicalEntry.Package.Hash = &models.RpmV001SchemaPackageHash{}
	canonicalEntry.Package.Hash.Algorithm = v.RPMModel.Package.Hash.Algorithm
	canonicalEntry.Package.Hash.Value = v.RPMModel.Package.Hash.Value
	// data content is not set deliberately

	// set NEVRA headers
	canonicalEntry.Package.Headers = make(map[string]string)
	canonicalEntry.Package.Headers["Name"] = rpmObj.Name()
	canonicalEntry.Package.Headers["Epoch"] = strconv.Itoa(rpmObj.Epoch())
	canonicalEntry.Package.Headers["Version"] = rpmObj.Version()
	canonicalEntry.Package.Headers["Release"] = rpmObj.Release()
	canonicalEntry.Package.Headers["Architecture"] = rpmObj.Architecture()
	if md5sum := rpmObj.GetBytes(0, 1004); md5sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_MD5"] = hex.EncodeToString(md5sum)
	}
	if sha1sum := rpmObj.GetBytes(0, 1012); sha1sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_SHA1"] = hex.EncodeToString(sha1sum)
	}
	if sha256sum := rpmObj.GetBytes(0, 1016); sha256sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_SHA256"] = hex.EncodeToString(sha256sum)
	}

	// wrap in valid object with kind and apiVersion set
	rpm := models.Rpm{}
	rpm.APIVersion = swag.String(APIVERSION)
	rpm.Spec = &canonicalEntry

	return json.Marshal(&rpm)
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() error {
	key := v.RPMModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if key.Content == nil || len(*key.Content) == 0 {
		return errors.New("'content' must be specified for publicKey")
	}

	pkg := v.RPMModel.Package
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
	returnVal := models.Rpm{}
	re := V001Entry{}

	// we will need artifact, public-key, signature
	re.RPMModel = models.RpmV001Schema{}
	re.RPMModel.Package = &models.RpmV001SchemaPackage{}

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
				return nil, fmt.Errorf("error reading RPM file: %w", err)
			}
		} else {
			artifactReader, err = os.Open(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error opening RPM file: %w", err)
			}
		}
		artifactBytes, err = io.ReadAll(artifactReader)
		if err != nil {
			return nil, fmt.Errorf("error reading RPM file: %w", err)
		}
	}
	re.RPMModel.Package.Content = strfmt.Base64(artifactBytes)

	re.RPMModel.PublicKey = &models.RpmV001SchemaPublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if len(publicKeyBytes) == 0 {
		if len(props.PublicKeyPaths) != 1 {
			return nil, errors.New("only one public key must be provided to verify RPM signature")
		}
		keyBytes, err := os.ReadFile(filepath.Clean(props.PublicKeyPaths[0].Path))
		if err != nil {
			return nil, fmt.Errorf("error reading public key file: %w", err)
		}
		publicKeyBytes = append(publicKeyBytes, keyBytes)
	} else if len(publicKeyBytes) != 1 {
		return nil, errors.New("only one public key must be provided")
	}

	re.RPMModel.PublicKey.Content = (*strfmt.Base64)(&publicKeyBytes[0])

	if err := re.validate(); err != nil {
		return nil, err
	}

	if _, _, err := re.fetchExternalEntities(context.Background()); err != nil {
		return nil, fmt.Errorf("error retrieving external entities: %w", err)
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.RPMModel

	return &returnVal, nil
}

func (v V001Entry) Verifiers() ([]pki.PublicKey, error) {
	if v.RPMModel.PublicKey == nil || v.RPMModel.PublicKey.Content == nil {
		return nil, errors.New("rpm v0.0.1 entry not initialized")
	}
	key, err := pgp.NewPublicKey(bytes.NewReader(*v.RPMModel.PublicKey.Content))
	if err != nil {
		return nil, err
	}
	return []pki.PublicKey{key}, nil
}

func (v V001Entry) ArtifactHash() (string, error) {
	if v.RPMModel.Package == nil || v.RPMModel.Package.Hash == nil || v.RPMModel.Package.Hash.Value == nil || v.RPMModel.Package.Hash.Algorithm == nil {
		return "", errors.New("rpm v0.0.1 entry not initialized")
	}
	return strings.ToLower(fmt.Sprintf("%s:%s", *v.RPMModel.Package.Hash.Algorithm, *v.RPMModel.Package.Hash.Value)), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.RPMModel.PublicKey == nil {
		return false, errors.New("missing publicKey property")
	}
	if v.RPMModel.PublicKey.Content == nil || len(*v.RPMModel.PublicKey.Content) == 0 {
		return false, errors.New("missing publicKey content")
	}

	if v.RPMModel.Package == nil {
		return false, errors.New("missing package property")
	}
	if len(v.RPMModel.Package.Content) == 0 {
		return false, errors.New("missing package content")
	}
	return true, nil
}
