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
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

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
	HelmObj                 models.HelmV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
	sigObj                  pki.Signature
	provenanceObj           *helm.Provenance
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

	algorithm, chartHash, err := v.provenanceObj.GetChartAlgorithmHash()

	if err != nil {
		log.Logger.Error(err)
	} else {
		hashKey := strings.ToLower(fmt.Sprintf("%s:%s", algorithm, chartHash))
		result = append(result, hashKey)
	}

	return result
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

func (v V001Entry) hasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.HelmObj.PublicKey != nil && v.HelmObj.PublicKey.URL.String() != "" {
		return true
	}
	if v.HelmObj.Chart != nil && v.HelmObj.Chart.Provenance != nil && v.HelmObj.Chart.Provenance.URL.String() != "" {
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

	artifactFactory, err := pki.NewArtifactFactory(pki.PGP)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	provenanceR, provenanceW := io.Pipe()

	defer provenanceR.Close()

	closePipesOnError := func(err error) error {
		pipeReaders := []*io.PipeReader{provenanceR}
		pipeWriters := []*io.PipeWriter{provenanceW}
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

	g.Go(func() error {
		defer provenanceW.Close()

		dataReadCloser, err := util.FileOrURLReadCloser(ctx, v.HelmObj.Chart.Provenance.URL.String(), v.HelmObj.Chart.Provenance.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer dataReadCloser.Close()

		/* #nosec G110 */
		if _, err := io.Copy(provenanceW, dataReadCloser); err != nil {
			return closePipesOnError(err)
		}
		return nil
	})

	keyResult := make(chan *pgp.PublicKey)

	g.Go(func() error {
		defer close(keyResult)
		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.HelmObj.PublicKey.URL.String(),
			v.HelmObj.PublicKey.Content)
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
		case keyResult <- v.keyObj.(*pgp.PublicKey):
			return nil
		}
	})

	g.Go(func() error {

		provenance := helm.Provenance{}
		if err := provenance.Unmarshal(provenanceR); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		key := <-keyResult
		if key == nil {
			return closePipesOnError(errors.New("error processing public key"))
		}

		// Set signature
		sig, err := artifactFactory.NewSignature(provenance.Block.ArmoredSignature.Body)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		// Verify signature
		if err := sig.Verify(bytes.NewReader(provenance.Block.Bytes), key); err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		v.sigObj = sig
		v.provenanceObj = &provenance

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	if err := g.Wait(); err != nil {
		return err
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

	canonicalEntry := models.HelmV001Schema{}

	var err error

	canonicalEntry.PublicKey = &models.HelmV001SchemaPublicKey{}
	keyContent, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.PublicKey.Content = (strfmt.Base64)(keyContent)

	canonicalEntry.Chart = &models.HelmV001SchemaChart{}

	algorithm, chartHash, err := v.provenanceObj.GetChartAlgorithmHash()

	if err != nil {
		return nil, err
	}

	canonicalEntry.Chart.Hash = &models.HelmV001SchemaChartHash{}
	canonicalEntry.Chart.Hash.Algorithm = &algorithm
	canonicalEntry.Chart.Hash.Value = &chartHash

	canonicalEntry.Chart.Provenance = &models.HelmV001SchemaChartProvenance{}
	canonicalEntry.Chart.Provenance.Signature = &models.HelmV001SchemaChartProvenanceSignature{}

	sigContent, err := v.sigObj.CanonicalValue()
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

	if len(key.Content) == 0 && key.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
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
		if len(provenance.Content) == 0 && provenance.URL.String() == "" {
			return errors.New("one of 'content' or 'url' must be specified for provenance")
		}
	}

	return nil
}

func (v V001Entry) Attestation() (string, []byte) {
	return "", nil
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
		if props.ArtifactPath.IsAbs() {
			re.HelmObj.Chart.Provenance.URL = strfmt.URI(props.ArtifactPath.String())
		} else {
			artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading artifact file: %w", err)
			}
			re.HelmObj.Chart.Provenance.Content = strfmt.Base64(artifactBytes)
		}
	} else {
		re.HelmObj.Chart.Provenance.Content = strfmt.Base64(artifactBytes)
	}

	re.HelmObj.PublicKey = &models.HelmV001SchemaPublicKey{}
	publicKeyBytes := props.PublicKeyBytes
	if publicKeyBytes == nil {
		if props.PublicKeyPath.IsAbs() {
			re.HelmObj.PublicKey.URL = strfmt.URI(props.PublicKeyPath.String())
		} else {
			publicKeyBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading public key file: %w", err)
			}
			re.HelmObj.PublicKey.Content = strfmt.Base64(publicKeyBytes)
		}
	} else {
		re.HelmObj.PublicKey.Content = strfmt.Base64(publicKeyBytes)
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
	returnVal.Spec = re.HelmObj

	return &returnVal, nil
}
