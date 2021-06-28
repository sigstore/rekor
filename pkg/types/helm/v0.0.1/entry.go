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

var (
	SHA256 = "sha256"
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
	provenanceObj           *helm.Provedance
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
		keyHash := sha256.Sum256(key)
		result = append(result, strings.ToLower(hex.EncodeToString(keyHash[:])))
	}

	result = append(result, v.keyObj.EmailAddresses()...)

	chartHash, err := v.provenanceObj.GetChartHash()

	if err != nil {
		log.Logger.Error(err)
	} else {
		result = append(result, chartHash)
	}

	//TODO: Store signature as index

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
	return nil

}

func (v V001Entry) HasExternalEntities() bool {

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

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {

	if v.fetchedExternalEntities {
		return nil
	}

	if err := v.Validate(); err != nil {
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

	artifactFactory := pki.NewArtifactFactory("pgp")

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
			return closePipesOnError(err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case keyResult <- v.keyObj.(*pgp.PublicKey):
			return nil
		}
	})

	g.Go(func() error {

		provenance := helm.Provedance{}
		if err := provenance.Unmarshal(provenanceR); err != nil {
			return closePipesOnError(err)
		}

		key := <-keyResult
		if key == nil {
			return closePipesOnError(errors.New("error processing public key"))
		}

		keyring, err := key.KeyRing()

		if err != nil {
			return closePipesOnError(errors.New("error obtaining keyring"))
		}

		// Make a copy of the reader so that it can be read multiple times
		var buf bytes.Buffer
		tee := io.TeeReader(provenance.ArmoredSignature.Body, &buf)

		if err := provenance.VerifySignature(keyring, tee); err != nil {
			return closePipesOnError(err)
		}

		// Set signature
		v.sigObj, err = artifactFactory.NewSignature(&buf)

		if err != nil {
			return errors.Wrap(err, "Error producing signature")
		}

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

	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}

	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.HelmV001Schema{}
	canonicalEntry.ExtraData = v.HelmObj.ExtraData

	var err error

	canonicalEntry.PublicKey = &models.HelmV001SchemaPublicKey{}
	keyContent, err := v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.PublicKey.Content = (strfmt.Base64)(keyContent)

	canonicalEntry.Chart = &models.HelmV001SchemaChart{}

	chartHash, err := v.provenanceObj.GetChartHash()

	if err != nil {
		return nil, err
	}

	canonicalEntry.Chart.Hash = &models.HelmV001SchemaChartHash{}
	canonicalEntry.Chart.Hash.Algorithm = &SHA256
	canonicalEntry.Chart.Hash.Value = &chartHash

	canonicalEntry.Chart.Provenance = &models.HelmV001SchemaChartProvenance{}
	canonicalEntry.Chart.Provenance.Signature = &models.HelmV001SchemaChartProvenanceSignature{}

	sigContent, err := v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Chart.Provenance.Signature.Content = (*strfmt.Base64)(&sigContent)

	// wrap in valid object with kind and apiVersion set
	helmObj := models.Helm{}
	helmObj.APIVersion = swag.String(APIVERSION)
	helmObj.Spec = &canonicalEntry

	bytes, err := json.Marshal(&helmObj)
	if err != nil {
		return nil, err
	}

	return bytes, nil

}

// Validate performs cross-field validation for fields in object
func (v V001Entry) Validate() error {

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

	if len(provenance.Content) == 0 && provenance.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for provenance")
	}

	return nil
}

func (v V001Entry) Attestation() (string, []byte) {
	return "", nil
}
