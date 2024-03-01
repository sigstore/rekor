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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/data"
	// This will support deprecated ECDSA hex-encoded keys in TUF metadata.
	// Will be removed when sigstore migrates entirely off hex-encoded.
	_ "github.com/theupdateframework/go-tuf/pkg/deprecated/set_ecdsa"
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
	TufObj models.TUFV001Schema
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) IndexKeys() ([]string, error) {
	var result []string
	keyBytes, err := v.parseRootContent()
	if err != nil {
		return nil, err
	}
	sigBytes, err := v.parseMetadataContent()
	if err != nil {
		return nil, err
	}
	key, err := ptuf.NewPublicKey(bytes.NewReader(keyBytes))
	if err != nil {
		return nil, err
	}
	sig, err := ptuf.NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		return nil, err
	}
	// Index metadata hash, type, and version.
	metadata, err := sig.CanonicalValue()
	if err != nil {
		return nil, err
	}

	metadataHash := sha256.Sum256(metadata)
	result = append(result, strings.ToLower(hex.EncodeToString(metadataHash[:])))

	result = append(result, sig.Role)
	result = append(result, strconv.Itoa(sig.Version))

	// Index root.json hash.
	root, err := key.CanonicalValue()
	if err != nil {
		log.Logger.Error(err)
	} else {
		rootHash := sha256.Sum256(root)
		result = append(result, strings.ToLower(hex.EncodeToString(rootHash[:])))
	}

	// TODO: Index individual key IDs
	return result, nil
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

func (v *V001Entry) fetchExternalEntities(ctx context.Context) (pki.PublicKey, pki.Signature, error) {
	g, ctx := errgroup.WithContext(ctx)

	metaR, metaW := io.Pipe()
	rootR, rootW := io.Pipe()
	defer metaR.Close()
	defer rootR.Close()

	closePipesOnError := types.PipeCloser(metaR, metaW, rootR, rootW)

	// verify artifact signature
	sigResult := make(chan pki.Signature)

	g.Go(func() error {
		defer close(sigResult)

		var contentBytes []byte
		if v.TufObj.Metadata.Content != nil {
			var err error
			contentBytes, err = v.parseMetadataContent()
			if err != nil {
				return closePipesOnError(err)
			}
		}

		sigReadCloser := bytes.NewReader(contentBytes)

		signature, err := ptuf.NewSignature(sigReadCloser)
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
			contentBytes, err = v.parseRootContent()
			if err != nil {
				return closePipesOnError(err)
			}
		}

		keyReadCloser := bytes.NewReader(contentBytes)

		key, err := ptuf.NewPublicKey(keyReadCloser)
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

	var (
		keyObj pki.PublicKey
		sigObj pki.Signature
	)
	// the sigObj contains the signed content.
	g.Go(func() error {
		keyObj, sigObj = <-keyResult, <-sigResult

		if keyObj == nil || sigObj == nil {
			return closePipesOnError(errors.New("failed to read signature or public key"))
		}

		var err error
		if err = sigObj.Verify(nil, keyObj); err != nil {
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
		return nil, nil, err
	}

	return keyObj, sigObj, nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	key, sig, err := v.fetchExternalEntities(ctx)
	if err != nil {
		return nil, err
	}

	canonicalEntry := models.TUFV001Schema{}

	canonicalEntry.SpecVersion, err = key.(*ptuf.PublicKey).SpecVersion()
	if err != nil {
		return nil, err
	}

	// need to canonicalize manifest (canonicalize JSON)
	canonicalEntry.Root = &models.TUFV001SchemaRoot{}
	canonicalEntry.Root.Content, err = key.CanonicalValue()
	if err != nil {
		return nil, err
	}

	canonicalEntry.Metadata = &models.TUFV001SchemaMetadata{}
	canonicalEntry.Metadata.Content, err = sig.CanonicalValue()
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
	if root.Content == nil {
		return errors.New("root must be specified")
	}

	tufManifest := v.TufObj.Metadata
	if tufManifest == nil {
		return errors.New("missing TUF metadata")
	}
	if tufManifest.Content == nil {
		return errors.New("TUF metadata must be specified")
	}
	return nil
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
	s := &data.Signed{}
	if err := json.Unmarshal(artifactBytes, s); err != nil {
		return nil, err
	}
	re.TufObj.Metadata.Content = s

	rootBytes := props.PublicKeyBytes
	re.TufObj.Root = &models.TUFV001SchemaRoot{}
	if len(rootBytes) == 0 {
		if len(props.PublicKeyPaths) != 1 {
			return nil, errors.New("only one path to root file must be specified")
		}
		keyBytes, err := os.ReadFile(filepath.Clean(props.PublicKeyPaths[0].Path))
		if err != nil {
			return nil, fmt.Errorf("error reading root file: %w", err)
		}
		rootBytes = append(rootBytes, keyBytes)

	} else if len(rootBytes) != 1 {
		return nil, errors.New("only one root key must be provided")
	}

	root := &data.Signed{}
	if err := json.Unmarshal(rootBytes[0], root); err != nil {
		return nil, err
	}
	re.TufObj.Root.Content = root

	if err := re.Validate(); err != nil {
		return nil, err
	}

	if _, _, err := re.fetchExternalEntities(ctx); err != nil {
		return nil, fmt.Errorf("error retrieving external entities: %w", err)
	}

	returnVal.APIVersion = swag.String(re.APIVersion())
	returnVal.Spec = re.TufObj

	return &returnVal, nil
}

func (v V001Entry) Verifiers() ([]pki.PublicKey, error) {
	if v.TufObj.Root == nil {
		return nil, errors.New("tuf v0.0.1 entry not initialized")
	}
	keyBytes, err := v.parseRootContent()
	if err != nil {
		return nil, err
	}
	key, err := ptuf.NewPublicKey(bytes.NewReader(keyBytes))
	if err != nil {
		return nil, err
	}
	return []pki.PublicKey{key}, nil
}

func (v V001Entry) ArtifactHash() (string, error) {
	if v.TufObj.Metadata == nil || v.TufObj.Metadata.Content == nil {
		return "", errors.New("tuf v0.0.1 entry not initialized")
	}
	sigBytes, err := v.parseMetadataContent()
	if err != nil {
		return "", err
	}
	sig, err := ptuf.NewSignature(bytes.NewReader(sigBytes))
	if err != nil {
		return "", err
	}
	metadata, err := sig.CanonicalValue()
	if err != nil {
		return "", err
	}
	metadataHash := sha256.Sum256(metadata)
	return strings.ToLower(fmt.Sprintf("sha256:%s", hex.EncodeToString(metadataHash[:]))), nil
}

func (v V001Entry) Insertable() (bool, error) {
	if v.TufObj.Metadata == nil {
		return false, errors.New("missing metadata property")
	}
	if v.TufObj.Metadata.Content == nil {
		return false, errors.New("missing metadata content")
	}

	if v.TufObj.Root == nil {
		return false, errors.New("missing root property")
	}
	if v.TufObj.Root.Content == nil {
		return false, errors.New("missing root content")
	}
	return true, nil
}

func (v V001Entry) parseRootContent() ([]byte, error) {
	var keyBytes []byte
	// Root.Content can either be a base64-encoded string or object
	switch v := v.TufObj.Root.Content.(type) {
	case string:
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding TUF root content: %w", err)
		}
		keyBytes = b
	default:
		var err error
		keyBytes, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	return keyBytes, nil
}

func (v V001Entry) parseMetadataContent() ([]byte, error) {
	var sigBytes []byte
	// Metadata.Content can either be a base64-encoded string or object
	switch v := v.TufObj.Metadata.Content.(type) {
	case string:
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("base64 decoding TUF metadata content: %w", err)
		}
		sigBytes = b
	default:
		var err error
		sigBytes, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	return sigBytes, nil
}
