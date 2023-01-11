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
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/pkcs7"
	"github.com/sigstore/rekor/pkg/pki/x509"
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
	JARModel models.JarV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v *V001Entry) IndexKeys() ([]string, error) {
	var result []string

	keyObj, err := pkcs7.NewSignature(bytes.NewReader(v.JARModel.Signature.Content))
	if err != nil {
		return nil, err
	}
	key, err := keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(key)
	result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))

	if v.JARModel.Archive.Hash != nil {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", *v.JARModel.Archive.Hash.Algorithm, *v.JARModel.Archive.Hash.Value))
		result = append(result, hashKey)
	}

	return result, nil
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

	return v.validate()
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (*pkcs7.PublicKey, *pkcs7.Signature, error) {
	if err := v.validate(); err != nil {
		return nil, nil, types.ValidationError(err)
	}

	oldSHA := ""
	if v.JARModel.Archive.Hash != nil && v.JARModel.Archive.Hash.Value != nil {
		oldSHA = swag.StringValue(v.JARModel.Archive.Hash.Value)
	}

	dataReadCloser := bytes.NewReader(v.JARModel.Archive.Content)

	hasher := sha256.New()
	b := &bytes.Buffer{}

	n, err := io.Copy(io.MultiWriter(hasher, b), dataReadCloser)
	if err != nil {
		return nil, nil, err
	}

	computedSHA := hex.EncodeToString(hasher.Sum(nil))
	if oldSHA != "" && computedSHA != oldSHA {
		return nil, nil, types.ValidationError(fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA))
	}

	zipReader, err := zip.NewReader(bytes.NewReader(b.Bytes()), n)
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	// this ensures that the JAR is signed and the signature verifies, as
	// well as checks that the hashes in the signed manifest are all valid
	jarObjs, err := jarutils.Verify(zipReader, false)
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}
	switch len(jarObjs) {
	case 0:
		return nil, nil, types.ValidationError(errors.New("no signatures detected in JAR archive"))
	case 1:
	default:
		return nil, nil, types.ValidationError(errors.New("multiple signatures detected in JAR; unable to process"))
	}

	// we need to find and extract the PKCS7 bundle from the JAR file manually
	sigPKCS7, err := extractPKCS7SignatureFromJAR(zipReader)
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	keyObj, err := pkcs7.NewPublicKey(bytes.NewReader(sigPKCS7))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	sigObj, err := pkcs7.NewSignature(bytes.NewReader(sigPKCS7))
	if err != nil {
		return nil, nil, types.ValidationError(err)
	}

	// if we get here, all goroutines succeeded without error
	if oldSHA == "" {
		v.JARModel.Archive.Hash = &models.JarV001SchemaArchiveHash{
			Algorithm: swag.String(models.JarV001SchemaArchiveHashAlgorithmSha256),
			Value:     swag.String(computedSHA),
		}

	}

	return keyObj, sigObj, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	keyObj, sigObj, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	// need to canonicalize key content
	keyContent, err := keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	sigContent, err := sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.JarV001Schema{
		Signature: &models.JarV001SchemaSignature{
			PublicKey: &models.JarV001SchemaSignaturePublicKey{
				Content: (*strfmt.Base64)(&keyContent),
			},
			Content: sigContent,
		},
		Archive: &models.JarV001SchemaArchive{
			Hash: &models.JarV001SchemaArchiveHash{
				Algorithm: v.JARModel.Archive.Hash.Algorithm,
				Value:     v.JARModel.Archive.Hash.Value,
			},
		},
	}
	// archive content is not set deliberately

	v.JARModel = canonicalEntry
	// wrap in valid object with kind and apiVersion set
	jar := models.Jar{}
	jar.APIVersion = swag.String(APIVERSION)
	jar.Spec = &canonicalEntry

	return json.Marshal(&jar)
}

// validate performs cross-field validation for fields in object
func (v *V001Entry) validate() error {
	archive := v.JARModel.Archive
	if archive == nil {
		return errors.New("missing package")
	}

	// if the signature isn't present, then we need content to extract
	if v.JARModel.Signature == nil || v.JARModel.Signature.Content == nil {
		if len(archive.Content) == 0 {
			return errors.New("'content' must be specified for package")
		}
	}

	hash := archive.Hash
	if hash != nil {
		if !govalidator.IsHash(swag.StringValue(hash.Value), swag.StringValue(hash.Algorithm)) {
			return errors.New("invalid value for hash")
		}
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
			contents, err := io.ReadAll(fileReader)
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

func (v *V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	returnVal := models.Jar{}
	re := V001Entry{}

	// we will need only the artifact; public-key & signature are embedded in JAR
	re.JARModel = models.JarV001Schema{}
	re.JARModel.Archive = &models.JarV001SchemaArchive{}

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
				return nil, fmt.Errorf("error reading JAR file: %w", err)
			}
		} else {
			artifactReader, err = os.Open(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error opening JAR file: %w", err)
			}
		}
		artifactBytes, err = io.ReadAll(artifactReader)
		if err != nil {
			return nil, fmt.Errorf("error reading JAR file: %w", err)
		}
	}
	re.JARModel.Archive.Content = (strfmt.Base64)(artifactBytes)

	if err := re.validate(); err != nil {
		return nil, err
	}

	if _, _, err := re.fetchExternalEntities(ctx); err != nil {
		return nil, fmt.Errorf("error retrieving external entities: %v", err)
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.JARModel

	return &returnVal, nil
}

func (v V001Entry) Verifier() (pki.PublicKey, error) {
	if v.JARModel.Signature == nil || v.JARModel.Signature.PublicKey == nil || v.JARModel.Signature.PublicKey.Content == nil {
		return nil, errors.New("jar v0.0.1 entry not initialized")
	}
	return x509.NewPublicKey(bytes.NewReader(*v.JARModel.Signature.PublicKey.Content))
}
