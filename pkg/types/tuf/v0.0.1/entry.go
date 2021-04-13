/*
Copyright © 2021 Bob Callaway <bcallawa@redhat.com>

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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	//"io"
	//"io/ioutil"
	"reflect"
	//"strconv"
	"strings"

	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/tuf"
	"github.com/sigstore/rekor/pkg/util"

	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/pki"

	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/sigstore/rekor/pkg/generated/models"
	"golang.org/x/sync/errgroup"
)

const (
	APIVERSION = "0.0.1"
)

func init() {
	tuf.SemVerToFacFnMap.Set(APIVERSION, NewEntry)
}

type V001Entry struct {
	TufModel                models.TufV001Schema
	fetchedExternalEntities bool
	keyObj                  pki.PublicKey
}

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func Base64StringtoByteArray() mapstructure.DecodeHookFunc {
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

	return result
}

func (v *V001Entry) Unmarshal(pe models.ProposedEntry) error {
	tuf, ok := pe.(*models.Tuf)
	if !ok {
		return errors.New("cannot unmarshal non tuf v0.0.1 type")
	}

	cfg := mapstructure.DecoderConfig{
		DecodeHook: Base64StringtoByteArray(),
		Result:     &v.TufModel,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	if err := dec.Decode(tuf.Spec); err != nil {
		return err
	}
	// field validation
	if err := v.TufModel.Validate(strfmt.Default); err != nil {
		return err
	}
	// cross field validation
	return v.Validate()

}

func (v V001Entry) HasExternalEntities() bool {
	if v.fetchedExternalEntities {
		return false
	}

	if v.TufModel.PublicKey != nil && v.TufModel.PublicKey.URL.String() != "" {
		return true
	}

	return false
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {

	keyResult := make(chan pki.PublicKey)

	g, ctx := errgroup.WithContext(ctx)

	// FIXME: we need to derive this "format" key parameter properly
	artifactFactory := pki.NewArtifactFactory("x509")
	g.Go(func() error {
		defer close(keyResult)

		keyReadCloser, err := util.FileOrURLReadCloser(ctx, v.TufModel.PublicKey.URL.String(),
			v.TufModel.PublicKey.Content)
		if err != nil {
			return err
		}
		defer keyReadCloser.Close()

		key, err := artifactFactory.NewPublicKey(keyReadCloser)
		fmt.Println(key)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case keyResult <- key:
			return nil
		}
	})

	g.Go(func() error {
		v.keyObj = <-keyResult

		if v.keyObj == nil {
			return errors.New("failed to read public key from remote location")
		}

		// FIXME: use metablock verification
		//var err error
		//if err = v.sigObj.Verify(sigR, v.keyObj); err != nil {
		//	return closePipesOnError(err)
		//}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	})

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {

	canonicalEntry := models.TufV001Schema{}
	canonicalEntry.ExtraData = v.TufModel.ExtraData

	var err error
	// need to canonicalize key content
	canonicalEntry.PublicKey = &models.TufV001SchemaPublicKey{}
	//canonicalEntry.PublicKey.Content, err = v.keyObj.CanonicalValue()
	if err != nil {
		return nil, err
	}

	// ExtraData is copied through unfiltered
	canonicalEntry.ExtraData = v.TufModel.ExtraData
	canonicalEntry.Metablock = v.TufModel.Metablock

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

//Validate performs cross-field validation for fields in object
// FIXME: we can probably export ValidateMetablock on in-toto.go
func (v V001Entry) Validate() error {
	key := v.TufModel.PublicKey
	if key == nil {
		return errors.New("missing public key")
	}
	if len(key.Content) == 0 && key.URL.String() == "" {
		return errors.New("one of 'content' or 'url' must be specified for publicKey")
	}

	tuf_doc := v.TufModel.Metablock
	if tuf_doc == nil {
		return errors.New("missing TUF metadata")
	}
	return nil
}
