/*
Copyright © 2021 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package tuf

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	cjson "github.com/tent/canonical-json-go"
	"golang.org/x/sync/errgroup"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/tuf"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/theupdateframework/go-tuf/data"

	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/pki"

	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	if err := tuf.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type BaseSigned struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int       `json:"version"`
}

type V001Entry struct {
	TufObj                  models.TufV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
	sigObj                  pki.Signature
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func base64StringtoByteArray() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Slice {
			return data, nil
		}

		bytes, err := base64.StdEncoding.DecodeString(data.(string))
		if err != nil {
			return []byte{}, fmt.Errorf("failed parsing base64 data: %v", err)
		}
		return bytes, nil
	}
}

func (v V001Entry) IndexKeys() []string {
	var result []string

	if v.HasExternalEntities() {
		if err := v.FetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	// Index manifest hash, type, and version.
	manifestHash := sha512.Sum512([]byte(v.TufObj.Manifest.Signed.Content))
	result = append(result, strings.ToLower(hex.EncodeToString(manifestHash[:])))
	result = append(result, v.TufObj.Manifest.Type)
	result = append(result, v.TufObj.Version)

	// Index root.json hash.
	root, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		rootHash := sha256.Sum256(root)
		result = append(result, strings.ToLower(hex.EncodeToString(rootHash[:])))
	}

	// TODO: Index individual key IDs?
	// TODO: Index a fully qualified URL into TUF metadata (e.g. OCI/project_name/type)?
	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	tuf, ok := pe.(*models.Tuf)
	if !ok {
		return errors.New("cannot unmarshal non tuf v0.0.1 type")
	}

	cfg := mapstructure.DecoderConfig{
		DecodeHook: base64StringtoByteArray(),
		Result:     &v.TufObj,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	if err := dec.Decode(tuf.Spec); err != nil {
		return err
	}
	// field validation
	if err := v.TufObj.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001Entry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.TufObj.Manifest != nil && v.TufObj.Manifest.Signed != nil && v.TufObj.Manifest.Signed.URL.String() != "" {
		return true
	}

	if v.TufObj.Root != nil && v.TufObj.Root.Signed != nil && v.TufObj.Root.Signed.URL.String() != "" {
		return true
	}

	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	if err := v.Validate(); err != nil {
		return types.ValidationError(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	metaR, metaW := io.Pipe()
	rootR, rootW := io.Pipe()
	defer metaR.Close()
	defer rootR.Close()

	closePipesOnError := func(err error) error {
		pipeReaders := []*io.PipeReader{metaR, rootR}
		pipeWriters := []*io.PipeWriter{metaW, rootW}
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

	// verify artifact signature
	artifactFactory, err := pki.NewArtifactFactory(pki.Format("tuf"))
	if err != nil {
		return err
	}

	sigResult := make(chan pki.Signature)

	g.Go(func() error {
		defer close(sigResult)

		sigReadCloser, err := util.FileOrURLReadCloser(ctx, v.TufObj.Manifest.Signed.URL.String(),
			v.TufObj.Manifest.Signed.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer sigReadCloser.Close()

		signature, err := artifactFactory.NewSignature(sigReadCloser)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case sigResult <- signature:
			return nil
		}
	})

	keyResult := make(chan pki.PublicKey)

	g.Go(func() error {
		defer close(keyResult)

		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.TufObj.Root.Signed.URL.String(),
			v.TufObj.Root.Signed.Content)
		if err != nil {
			return closePipesOnError(err)
		}
		defer keyReadCloser.Close()

		key, err := artifactFactory.NewPublicKey(keyReadCloser)
		if err != nil {
			return closePipesOnError(types.ValidationError(err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case keyResult <- key:
			return nil
		}
	})

	// the sigObj contains the signed content.
	g.Go(func() error {
		v.keyObj, v.sigObj = <-keyResult, <-sigResult

		if v.keyObj == nil || v.sigObj == nil {
			return closePipesOnError(errors.New("failed to read signature or public key"))
		}

		var err error
		if err = v.sigObj.Verify(nil, v.keyObj); err != nil {
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
		return err
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.sigObj == nil {
		return nil, errors.New("signature object not initialized before canonicalization")
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.TufV001Schema{}
	canonicalEntry.ExtraData = v.TufObj.ExtraData

	// need to canonicalize manifest (canonicalize JSON)
	var err error
	canonicalEntry.Root = &models.TufManifestV001Schema{Signed: &models.TufManifestV001SchemaSigned{}}
	canonicalEntry.Root.Signed.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.Root.Version = v.TufObj.Root.Version
	canonicalEntry.Root.Expires = v.TufObj.Root.Expires
	canonicalEntry.Root.Type = v.TufObj.Root.Type

	canonicalEntry.Manifest = &models.TufManifestV001Schema{Signed: &models.TufManifestV001SchemaSigned{}}
	canonicalEntry.Manifest.Signed.Content, err = v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	canonicalEntry.Manifest.Version = v.TufObj.Manifest.Version
	canonicalEntry.Manifest.Expires = v.TufObj.Manifest.Expires
	canonicalEntry.Manifest.Type = v.TufObj.Manifest.Type

	// wrap in valid object with kind and apiVersion set
	tuf := models.Tuf{}
	tuf.APIVersion = swag.String(APIVERSION)
	tuf.Spec = &canonicalEntry

	bytes, err := json.Marshal(&tuf)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}

// Validate performs cross-field validation for fields in object
// FIXME: we can probably export ValidateMetablock on in-toto.go
func (v V001Entry) Validate() error {
	root := v.TufObj.Root
	if root == nil || root.Signed == nil {
		return errors.New("missing root")
	}
	if len(root.Signed.Content) == 0 && root.Signed.URL.String() == "" {
		return errors.New("root must be specified")
	}

	tufManifest := v.TufObj.Manifest
	if tufManifest == nil || tufManifest.Signed == nil {
		return errors.New("missing TUF metadata")
	}
	if len(tufManifest.Signed.Content) == 0 && tufManifest.Signed.URL.String() == "" {
		return errors.New("TUF metadata must be specified")
	}
	return nil
}

func (v *V001Entry) Attestation() (string, []byte) {
	return "", nil
}

func createTufManifest(manifest []byte) (*models.TufManifestV001Schema, error) {
	re := &models.TufManifestV001Schema{}
	s := &data.Signed{}
	if err := json.Unmarshal(manifest, s); err != nil {
		return nil, err
	}
	baseSigned := &BaseSigned{}
	if err := json.Unmarshal(s.Signed, baseSigned); err != nil {
		return nil, err
	}
	// Canonicalize the JSON of the entire manifest
	var decoded map[string]interface{}
	if err := json.Unmarshal(manifest, &decoded); err != nil {
		return nil, err
	}
	msg, err := cjson.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	re.Signed = &models.TufManifestV001SchemaSigned{Content: strfmt.Base64(msg)}
	re.Expires = baseSigned.Expires.String()
	re.Type = baseSigned.Type
	re.Version = int64(baseSigned.Version)
	return re, nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	// This will do only syntactic checks of the metablock, not signature verification.
	// Signature verification occurs in FetchExternalEntries()
	returnVal := models.Tuf{}
	re := V001Entry{}
	re.TufObj.Version = "1.0.0" // TODO: Get tuf specification for root manifest

	// we will need the manifest and root
	// Not sure why but only ArtifactPath is ever set with a filepath name
	var err error
	artifactBytes, err := ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
	if err != nil {
		return nil, fmt.Errorf("error reading artifact file: %w", err)
	}
	re.TufObj.Manifest, err = createTufManifest(artifactBytes)
	if err != nil {
		return nil, err
	}
	rootBytes, err := ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
	if err != nil {
		return nil, fmt.Errorf("error reading root file: %w", err)
	}
	re.TufObj.Root, err = createTufManifest(rootBytes)
	if err != nil {
		return nil, err
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.TufObj

	return &returnVal, nil
}
