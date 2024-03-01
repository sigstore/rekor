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

package helm

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

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/pki"
	"github.com/sigstore/rekor/pkg/pki/pgp"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/helm"
	"github.com/sigstore/rekor/pkg/util"
	"golang.org/x/sync/errgroup"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := helm.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	HelmObj models.HelmV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string

	keyObj, err := pgp.NewPublicKey(bytes.NewReader(*v.HelmObj.PublicKey.Content))
	if err != nil {
		return nil, err
	}

	provenance := helm.Provenance{}
	if err := provenance.Unmarshal(bytes.NewReader(v.HelmObj.Chart.Provenance.Content)); err != nil {
		return nil, err
	}

	key, err := keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(key)
	result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))

	result = append(result, keyObj.Subjects()...)

	algorithm, chartHash, err := provenance.GetChartAlgorithmHash()

	if err != nil {
		log.Logger.Error(err)
	} else {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", algorithm, chartHash))
		result = append(result, hashKey)
	}

	return result, nil
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {

	helm, ok := pe.(*models.Helm)
	if !ok {
		return errors.New("cannot unmarshal non Helm v0.0.1 type")
	}

	if err := types.DecodeEntry(helm.Spec, &v.HelmObj); err != nil {
		return err
	}

	// field validation
	if err := v.HelmObj.Validate(strfmt.Default); err != nil {
		return err
	}

	// cross field validation
	return v.validate()
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (*helm.Provenance, *pgp.PublicKey, *pgp.Signature, error) {
	if err := v.validate(); err != nil {
		return nil, nil, nil, types.ValidationError(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	provenanceR, provenanceW := io.Pipe()
	defer provenanceR.Close()

	closePipesOnError := types.PipeCloser(provenanceR, provenanceW)

	g.Go(func() error {
		defer provenanceW.Close()

		dataReadCloser := bytes.NewReader(v.HelmObj.Chart.Provenance.Content)

		/* #nosec G110 */
		if _, err := io.Copy(provenanceW, dataReadCloser); err != nil {
			return closePipesOnError(err)
		}
		return nil
	})

	keyResult := make(chan *pgp.PublicKey)

	g.Go(func() error {
		defer close(keyResult)
		keyReadCloser := bytes.NewReader(*v.HelmObj.PublicKey.Content)

		keyObj, err := pgp.NewPublicKey(keyReadCloser)
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

	var key *pgp.PublicKey
	provenance := &helm.Provenance{}
	var sig *pgp.Signature
	g.Go(func() error {

		if err := provenance.Unmarshal(provenanceR); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		key = <-keyResult
		if key == nil {
			return closePipesOnError(errors.New("error processing public key"))
		}

		// Set signature
		var err error
		sig, err = pgp.NewSignature(provenance.Block.ArmoredSignature.Body)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		// Verify signature
		if err := sig.Verify(bytes.NewReader(provenance.Block.Bytes), key); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	if err := g.Wait(); err != nil {
		return nil, nil, nil, err
	}

	return provenance, key, sig, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	provenanceObj, keyObj, sigObj, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	if keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.HelmV001Schema{}

	canonicalEntry.PublicKey = &models.HelmV001SchemaPublicKey{}
	keyContent, err := keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.PublicKey.Content = (*strfmt.Base64)(&keyContent)

	canonicalEntry.Chart = &models.HelmV001SchemaChart{}

	algorithm, chartHash, err := provenanceObj.GetChartAlgorithmHash()

	if err != nil {
		return nil, err
	}

	canonicalEntry.Chart.Hash = &models.HelmV001SchemaChartHash{}
	canonicalEntry.Chart.Hash.Algorithm = &algorithm
	canonicalEntry.Chart.Hash.Value = &chartHash

	canonicalEntry.Chart.Provenance = &models.HelmV001SchemaChartProvenance{}
	canonicalEntry.Chart.Provenance.Signature = &models.HelmV001SchemaChartProvenanceSignature{}

	sigContent, err := sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Chart.Provenance.Signature.Content = sigContent

	// wrap in valid object with kind and apiVersion set
	helmObj := models.Helm{}
	helmObj.APIVersion = swag.String(APIVERSION)
	helmObj.Spec = &canonicalEntry

	return json.Marshal(&helmObj)
}

// validate performs cross-field validation for fields in object
func (v V001Entry) validate() error {

	key := v.HelmObj.PublicKey

	if key == nil {
		return errors.New("missing public key")
	}

	if key.Content == nil || len(*key.Content) == 0 {
		return errors.New("'content' must be specified for publicKey")
	}

	chart := v.HelmObj.Chart

	if chart == nil {
		return errors.New("missing chart")
	}

	provenance := chart.Provenance

	if provenance == nil {
		return errors.New("missing provenance")
	}

	if provenance.Signature == nil || provenance.Signature.Content == nil {
		if len(provenance.Content) == 0 {
			return errors.New("'content' must be specified for provenance")
		}
	}

	return nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	//TODO: how to select version of item to create
	returnVal := models.Helm{}
	re := V001Entry{}

	// we will need provenance file and public-key
	re.HelmObj = models.HelmV001Schema{}
	re.HelmObj.Chart = &models.HelmV001SchemaChart{}
	re.HelmObj.Chart.Provenance = &models.HelmV001SchemaChartProvenance{}

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
				return nil, fmt.Errorf("error reading chart file: %w", err)
			}
		} else {
			artifactReader, err = os.Open(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error opening chart file: %w", err)
			}
		}
		artifactBytes, err = io.ReadAll(artifactReader)
		if err != nil {
			return nil, fmt.Errorf("error reading chart file: %w", err)
		}
	}
	re.HelmObj.Chart.Provenance.Content = strfmt.Base64(artifactBytes)

	re.HelmObj.PublicKey = &models.HelmV001SchemaPublicKey{}
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

	re.HelmObj.PublicKey.Content = (*strfmt.Base64)(&publicKeyBytes[0])
	if err := re.validate(); err != nil {
		return nil, err
	}

	if _, _, _, err := re.fetchExternalEntities(ctx); err != nil {
		return nil, fmt.Errorf("error retrieving external entities: %w", err)
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.HelmObj

	return &returnVal, nil
}

func (v V001Entry) Verifiers() ([]pki.PublicKey, error) {
	if v.HelmObj.PublicKey == nil || v.HelmObj.PublicKey.Content == nil {
		return nil, errors.New("helm v0.0.1 entry not initialized")
	}
	key, err := pgp.NewPublicKey(bytes.NewReader(*v.HelmObj.PublicKey.Content))
	if err != nil {
		return nil, err
	}
	return []pki.PublicKey{key}, nil
}

func (v V001Entry) ArtifactHash() (string, error) {
	if v.HelmObj.Chart == nil || v.HelmObj.Chart.Hash == nil || v.HelmObj.Chart.Hash.Algorithm == nil || v.HelmObj.Chart.Hash.Value == nil {
		return "", errors.New("helm v0.0.1 entry not initialized")
	}
	return strings.ToLower(fmt.Sprintf("%s:%s", *v.HelmObj.Chart.Hash.Algorithm, *v.HelmObj.Chart.Hash.Value)), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.HelmObj.PublicKey == nil {
		return false, errors.New("missing public key property")
	}
	if v.HelmObj.PublicKey.Content == nil || len(*v.HelmObj.PublicKey.Content) == 0 {
		return false, errors.New("missing public key content")
	}

	if v.HelmObj.Chart == nil {
		return false, errors.New("missing chart property")
	}
	if v.HelmObj.Chart.Provenance == nil {
		return false, errors.New("missing provenance property")
	}
	if len(v.HelmObj.Chart.Provenance.Content) == 0 {
		return false, errors.New("missing provenance content")
	}
	return true, nil
}
