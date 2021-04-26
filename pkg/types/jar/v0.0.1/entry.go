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

package jar

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/jar"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/asaskevich/govalidator"

	"github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
	jarutils "github.com/sassoftware/relic/lib/signjar"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := jar.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	JARModel                models.JarV001Schema
	fetchedExternalEntities bool
	jarObj                  *jarutils.JarSignature
	keyObj                  pki.PublicKey
	sigObj                  pki.Signature
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

	if v.JARModel.Archive.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.JARModel.Archive.Hash.Algorithm, *v.JARModel.Archive.Hash.Value))
		result = append(result, hashKey)
	}

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	jar, ok := pe.(*models.Jar)
	if !ok {
		return errors.New("cannot unmarshal non JAR v0.0.1 type")
	}

	if err := types.DecodeEntry(jar.Spec, &v.JARModel); err != nil {
		return err
	}

	// field validation
	if err := v.JARModel.Validate(strfmt.Default); err != nil {
		return err
	}
	return nil

}

func (v V001Entry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.JARModel.Archive != nil && v.JARModel.Archive.URL.String() != "" {
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

	oldSHA := ""
	if v.JARModel.Archive.Hash != nil && v.JARModel.Archive.Hash.Value != nil {
		oldSHA = swag.StringValue(v.JARModel.Archive.Hash.Value)
	}

	dataReadCloser, err := util.FileOrURLReadCloser(ctx, v.JARModel.Archive.URL.String(), v.JARModel.Archive.Content)
	if err != nil {
		return err
	}
	defer dataReadCloser.Close()

	hasher := sha256.New()
	b := &bytes.Buffer{}

	n, err := io.Copy(io.MultiWriter(hasher, b), dataReadCloser)
	if err != nil {
		return err
	}

	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if oldSHA != "" && computedSHA != oldSHA {
		return fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA)
	}

	zipReader, err := zip.NewReader(bytes.NewReader(b.Bytes()), n)
	if err != nil {
		return err
	}

	// this ensures that the JAR is signed and the signature verifies, as
	// well as checks that the hashes in the signed manifest are all valid
	jarObj, err := jarutils.Verify(zipReader, false)
	if err != nil {
		return err
	}
	switch len(jarObj) {
	case 0:
		return errors.New("no signatures detected in JAR archive")
	case 1:
	default:
		return errors.New("multiple signatures detected in JAR; unable to process")
	}
	v.jarObj = jarObj[0]

	af := pki.NewArtifactFactory("pkcs7")
	// we need to find and extract the PKCS7 bundle from the JAR file manually
	sigPKCS7, err := extractPKCS7SignatureFromJAR(zipReader)
	if err != nil {
		return err
	}

	v.keyObj, err = af.NewPublicKey(bytes.NewReader(sigPKCS7))
	if err != nil {
		return err
	}

	v.sigObj, err = af.NewSignature(bytes.NewReader(sigPKCS7))
	if err != nil {
		return err
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.JARModel.Archive.Hash = &models.JarV001SchemaArchiveHash{}
		v.JARModel.Archive.Hash.Algorithm = swag.String(models.JarV001SchemaArchiveHashAlgorithmSha256)
		v.JARModel.Archive.Hash.Value = swag.String(computedSHA)
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.jarObj == nil {
		return nil, errors.New("JAR object not initialized before canonicalization")
	}
	if v.keyObj == nil {
		return nil, errors.New("public key not initialized before canonicalization")
	}
	if v.sigObj == nil {
		return nil, errors.New("signature not initialized before canonicalization")
	}

	canonicalEntry := models.JarV001Schema{}
	canonicalEntry.ExtraData = v.JARModel.ExtraData

	var err error
	// need to canonicalize key content
	canonicalEntry.Signature = &models.JarV001SchemaSignature{}
	canonicalEntry.Signature.PublicKey = &models.JarV001SchemaSignaturePublicKey{}
	keyContent, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.Signature.PublicKey.Content = (*strfmt.Base64)(&keyContent)
	sigContent, err := v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.Signature.Content = (*strfmt.Base64)(&sigContent)

	canonicalEntry.Archive = &models.JarV001SchemaArchive{}
	canonicalEntry.Archive.Hash = &models.JarV001SchemaArchiveHash{}
	canonicalEntry.Archive.Hash.Algorithm = v.JARModel.Archive.Hash.Algorithm
	canonicalEntry.Archive.Hash.Value = v.JARModel.Archive.Hash.Value
	// archive content is not set deliberately

	// ExtraData is copied through unfiltered
	canonicalEntry.ExtraData = v.JARModel.ExtraData

	// wrap in valid object with kind and apiVersion set
	jar := models.Jar{}
	jar.APIVersion = swag.String(APIVERSION)
	jar.Spec = &canonicalEntry

	bytes, err := json.Marshal(&jar)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// Validate performs cross-field validation for fields in object
func (v V001Entry) Validate() error {
	archive := v.JARModel.Archive
	if archive == nil {
		return errors.New("missing package")
	}

	if len(archive.Content) == 0 && archive.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for package")
	}

	hash := archive.Hash
	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
	} else if archive.URL.String() != "" {
		return errors.New("hash value must be provided if URL is specified")
	}

	return nil
}

// extractPKCS7SignatureFromJAR extracts the first signature file from the JAR and returns it
func extractPKCS7SignatureFromJAR(inz *zip.Reader) ([]byte, error) {
	for _, f := range inz.File {
		dir, name := path.Split(strings.ToUpper(f.Name))
		if dir != "META-INF/" || name == "" {
			continue
		}
		i := strings.LastIndex(name, ".")
		if i < 0 {
			continue
		}
		fileExt := name[i:]
		if fileExt == ".RSA" || fileExt == ".DSA" || fileExt == ".EC" || strings.HasPrefix(name, "SIG-") {
			fileReader, err := f.Open()
			if err != nil {
				return nil, err
			}
			contents, err := ioutil.ReadAll(fileReader)
			if err != nil {
				return nil, err
			}
			if err = fileReader.Close(); err != nil {
				return nil, err
			}
			return contents, nil
		}
	}
	return nil, errors.New("unable to locate signature in JAR file")
}
