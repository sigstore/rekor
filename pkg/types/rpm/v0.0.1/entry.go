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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
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
	RPMModel                models.RpmV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
	rpmObj                  *rpmutils.PackageFile
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	if v.HasExternalEntities() {
		if err := v.FetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	key, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		hasher := sha256.New()
		if _, err := hasher.Write(key); err != nil {
			log.Logger.Error(err)
		} else {
			result = append(result, strings.ToLower(hex.EncodeToString(hasher.Sum(nil))))
		}
	}

	result = append(result, v.keyObj.EmailAddresses()...)

	if v.RPMModel.Package.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.RPMModel.Package.Hash.Algorithm, *v.RPMModel.Package.Hash.Value))
		result = append(result, hashKey)
	}

	return result
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
	return nil

}

func (v V001Entry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.RPMModel.Package != nil && v.RPMModel.Package.URL.String() != "" {
		return true
	}
	if v.RPMModel.PublicKey != nil && v.RPMModel.PublicKey.URL.String() != "" {
		return true
	}
	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	if v.fetchedExternalEntities {
		return nil
	}

	if err := v.Validate(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	sigR, sigW := io.Pipe()
	rpmR, rpmW := io.Pipe()
	defer hashR.Close()
	defer sigR.Close()
	defer rpmR.Close()

	closePipesOnError := func(err error) error {
		pipeReaders := []*io.PipeReader{hashR, sigR, rpmR}
		pipeWriters := []*io.PipeWriter{hashW, sigW, rpmW}
		for idx := range pipeReaders {
			if e := pipeReaders[idx].CloseWithError(err); e != nil {
				log.Logger.Error(fmt.Errorf("error closing pipe: %w", e))
			}
			if e := pipeWriters[idx].CloseWithError(err); e != nil {
				log.Logger.Error(fmt.Errorf("error closing pipe: %w", e))
			}
		}
		return err
	}

	oldSHA := ""
	if v.RPMModel.Package.Hash != nil && v.RPMModel.Package.Hash.Value != nil {
		oldSHA = swag.StringValue(v.RPMModel.Package.Hash.Value)
	}
	artifactFactory := pki.NewArtifactFactory("pgp")

	g.Go(func() error {
		defer hashW.Close()
		defer sigW.Close()
		defer rpmW.Close()

		dataReadCloser, err := util.FileOrURLReadCloser(ctx, v.RPMModel.Package.URL.String(), v.RPMModel.Package.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer dataReadCloser.Close()

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
			return closePipesOnError(fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case hashResult <- computedSHA:
			return nil
		}
	})

	g.Go(func() error {
		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.RPMModel.PublicKey.URL.String(),
			v.RPMModel.PublicKey.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer keyReadCloser.Close()

		v.keyObj, err = artifactFactory.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(err)
		}

		keyring, err := v.keyObj.(*pgp.PublicKey).KeyRing()
		if err != nil {
			return closePipesOnError(err)
		}

		if _, err := rpmutils.GPGCheck(sigR, keyring); err != nil {
			return closePipesOnError(err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	g.Go(func() error {

		var err error
		v.rpmObj, err = rpmutils.ReadPackageFile(rpmR)
		if err != nil {
			return closePipesOnError(err)
		}
		// ReadPackageFile does not drain the entire reader so we need to discard the rest
		if _, err = io.Copy(ioutil.Discard, rpmR); err != nil {
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
		return err
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.RPMModel.Package.Hash = &models.RpmV001SchemaPackageHash{}
		v.RPMModel.Package.Hash.Algorithm = swag.String(models.RpmV001SchemaPackageHashAlgorithmSha256)
		v.RPMModel.Package.Hash.Value = swag.String(computedSHA)
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.RpmV001Schema{}
	canonicalEntry.ExtraData = v.RPMModel.ExtraData

	var err error
	// need to canonicalize key content
	canonicalEntry.PublicKey = &models.RpmV001SchemaPublicKey{}
	canonicalEntry.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Package = &models.RpmV001SchemaPackage{}
	canonicalEntry.Package.Hash = &models.RpmV001SchemaPackageHash{}
	canonicalEntry.Package.Hash.Algorithm = v.RPMModel.Package.Hash.Algorithm
	canonicalEntry.Package.Hash.Value = v.RPMModel.Package.Hash.Value
	// data content is not set deliberately

	// set NEVRA headers
	canonicalEntry.Package.Headers = make(map[string]string)
	canonicalEntry.Package.Headers["Name"] = v.rpmObj.Name()
	canonicalEntry.Package.Headers["Epoch"] = strconv.Itoa(v.rpmObj.Epoch())
	canonicalEntry.Package.Headers["Version"] = v.rpmObj.Version()
	canonicalEntry.Package.Headers["Release"] = v.rpmObj.Release()
	canonicalEntry.Package.Headers["Architecture"] = v.rpmObj.Architecture()
	if md5sum := v.rpmObj.GetBytes(0, 1004); md5sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_MD5"] = hex.EncodeToString(md5sum)
	}
	if sha1sum := v.rpmObj.GetBytes(0, 1012); sha1sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_SHA1"] = hex.EncodeToString(sha1sum)
	}
	if sha256sum := v.rpmObj.GetBytes(0, 1016); sha256sum != nil {
		canonicalEntry.Package.Headers["RPMSIGTAG_SHA256"] = hex.EncodeToString(sha256sum)
	}

	// ExtraData is copied through unfiltered
	canonicalEntry.ExtraData = v.RPMModel.ExtraData

	// wrap in valid object with kind and apiVersion set
	rpm := models.Rpm{}
	rpm.APIVersion = swag.String(APIVERSION)
	rpm.Spec = &canonicalEntry

	bytes, err := json.Marshal(&rpm)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// Validate performs cross-field validation for fields in object
func (v V001Entry) Validate() error {
	key := v.RPMModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 && key.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
	}

	pkg := v.RPMModel.Package
	if pkg == nil {
		return errors.New("missing package")
	}

	if len(pkg.Content) == 0 && pkg.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for package")
	}

	hash := pkg.Hash
	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
	}

	return nil
}
