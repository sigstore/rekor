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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/data"
	"golang.org/x/sync/errgroup"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/tuf"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/pki"
	ptuf "github.com/sigstore/rekor/pkg/pki/tuf"

	"github.com/go-openapi/swag"
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
	TufObj                  models.TUFV001Schema
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

func (v V001Entry) IndexKeys() []string {
	var result []string

	if v.hasExternalEntities() {
		if err := v.fetchExternalEntities(context.Background()); err != nil {
			log.Logger.Error(err)
			return result
		}
	}

	// Index metadata hash, type, and version.
	metadata, err := v.sigObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		metadataHash := sha256.Sum256(metadata)
		result = append(result, strings.ToLower(hex.EncodeToString(metadataHash[:])))
	}

	signed, ok := v.sigObj.(*ptuf.Signature)
	if !ok {
		log.Logger.Error(errors.New("invalid metadata format"))
		return result
	}

	result = append(result, signed.Role)
	result = append(result, strconv.Itoa(signed.Version))

	// Index root.json hash.
	root, err := v.keyObj.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		rootHash := sha256.Sum256(root)
		result = append(result, strings.ToLower(hex.EncodeToString(rootHash[:])))
	}

	// TODO: Index individual key IDs
	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	tuf, ok := pe.(*models.TUF)
	if !ok {
		return errors.New("cannot unmarshal non tuf v0.0.1 type")
	}

	if err := types.DecodeEntry(tuf.Spec, &v.TufObj); err != nil {
		return err
	}

	// field validation
	if err := v.TufObj.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001Entry) hasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.TufObj.Metadata != nil && v.TufObj.Metadata.URL.String() != "" {
		return true
	}

	if v.TufObj.Root != nil && v.TufObj.Root.URL.String() != "" {
		return true
	}

	return false
}

func (v *V001Entry) fetchExternalEntities(ctx context.Context) error {
	if err := v.Validate(); err != nil {
		return types.ValidationError(err)
	}

	g, ctx := errgroup.WithContext(ctx)

	metaR, metaW := io.Pipe()
	rootR, rootW := io.Pipe()
	defer metaR.Close()
	defer rootR.Close()

	closePipesOnError := types.PipeCloser(metaR, metaW, rootR, rootW)

	// verify artifact signature
	artifactFactory, err := pki.NewArtifactFactory(pki.Tuf)
	if err != nil {
		return err
	}

	sigResult := make(chan pki.Signature)

	g.Go(func() error {
		defer close(sigResult)

		var contentBytes []byte
		if v.TufObj.Metadata.Content != nil {
			var err error
			contentBytes, err = json.Marshal(v.TufObj.Metadata.Content)
			if err != nil {
				return closePipesOnError(err)
			}
		}

		sigReadCloser, err := util.FileOrURLReadCloser(ctx, v.TufObj.Metadata.URL.String(),
			contentBytes)
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

		var contentBytes []byte
		if v.TufObj.Root.Content != nil {
			var err error
			contentBytes, err = json.Marshal(v.TufObj.Root.Content)
			if err != nil {
				return closePipesOnError(err)
			}
		}

		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.TufObj.Root.URL.String(),
			contentBytes)
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
	if err := v.fetchExternalEntities(ctx); err != nil {
		return nil, err
	}
	if v.sigObj == nil {
		return nil, errors.New("signature object not initialized before canonicalization")
	}
	if v.keyObj == nil {
		return nil, errors.New("key object not initialized before canonicalization")
	}

	canonicalEntry := models.TUFV001Schema{}

	var err error
	canonicalEntry.SpecVersion, err = v.keyObj.(*ptuf.PublicKey).SpecVersion()
	if err != nil {
		return nil, err
	}

	// need to canonicalize manifest (canonicalize JSON)
	canonicalEntry.Root = &models.TUFV001SchemaRoot{}
	canonicalEntry.Root.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Metadata = &models.TUFV001SchemaMetadata{}
	canonicalEntry.Metadata.Content, err = v.sigObj.CanonicalValue()
	if err != nil {
		return nil, err
	}
	// wrap in valid object with kind and apiVersion set
	tuf := models.TUF{}
	tuf.APIVersion = swag.String(APIVERSION)
	tuf.Spec = &canonicalEntry

	return json.Marshal(&tuf)
}

// Validate performs cross-field validation for fields in object
// FIXME: we can probably export ValidateMetablock on in-toto.go
func (v V001Entry) Validate() error {
	root := v.TufObj.Root
	if root == nil {
		return errors.New("missing root")
	}
	if root.Content == nil && root.URL.String() == "" {
		return errors.New("root must be specified")
	}

	tufManifest := v.TufObj.Metadata
	if tufManifest == nil {
		return errors.New("missing TUF metadata")
	}
	if tufManifest.Content == nil && tufManifest.URL.String() == "" {
		return errors.New("TUF metadata must be specified")
	}
	return nil
}

func (v *V001Entry) Attestation() (string, []byte) {
	return "", nil
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, props types.ArtifactProperties) (models.ProposedEntry, error) {
	// This will do only syntactic checks of the metablock, not signature verification.
	// Signature verification occurs in FetchExternalEntries()
	returnVal := models.TUF{}
	re := V001Entry{}

	// we will need the manifest and root
	var err error
	artifactBytes := props.ArtifactBytes
	re.TufObj.Metadata = &models.TUFV001SchemaMetadata{}
	if artifactBytes == nil {
		if props.ArtifactPath == nil {
			return nil, errors.New("path to manifest (file or URL) must be specified")
		}
		if props.ArtifactPath.IsAbs() {
			re.TufObj.Metadata.URL = strfmt.URI(props.ArtifactPath.String())
		} else {
			artifactBytes, err = ioutil.ReadFile(filepath.Clean(props.ArtifactPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading manifest file: %w", err)
			}
			s := &data.Signed{}
			if err := json.Unmarshal(artifactBytes, s); err != nil {
				return nil, err
			}
			re.TufObj.Metadata.Content = s
		}
	} else {
		s := &data.Signed{}
		if err := json.Unmarshal(artifactBytes, s); err != nil {
			return nil, err
		}
		re.TufObj.Metadata.Content = s
	}

	rootBytes := props.PublicKeyBytes
	re.TufObj.Root = &models.TUFV001SchemaRoot{}
	if rootBytes == nil {
		if props.PublicKeyPath == nil {
			return nil, errors.New("path to root (file or URL) must be specified")
		}
		if props.PublicKeyPath.IsAbs() {
			re.TufObj.Root.URL = strfmt.URI(props.PublicKeyPath.String())
		} else {
			rootBytes, err = ioutil.ReadFile(filepath.Clean(props.PublicKeyPath.Path))
			if err != nil {
				return nil, fmt.Errorf("error reading root file: %w", err)
			}
			s := &data.Signed{}
			if err := json.Unmarshal(rootBytes, s); err != nil {
				return nil, err
			}
			re.TufObj.Root.Content = s
		}
	} else {
		s := &data.Signed{}
		if err := json.Unmarshal(rootBytes, s); err != nil {
			return nil, err
		}
		re.TufObj.Root.Content = s
	}

	if err := re.Validate(); err != nil {
		return nil, err
	}

	if re.hasExternalEntities() {
		if err := re.fetchExternalEntities(ctx); err != nil {
			return nil, fmt.Errorf("error retrieving external entities: %v", err)
		}
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.TufObj

	return &returnVal, nil
}
