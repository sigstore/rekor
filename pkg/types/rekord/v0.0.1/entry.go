/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

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
package rekord

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"

	"github.com/projectrekor/rekor/pkg/pki"

	"github.com/go-openapi/swag"
	"github.com/mitchellh/mapstructure"
	"github.com/projectrekor/rekor/pkg/generated/models"
	"golang.org/x/sync/errgroup"
)

type V001Entry struct {
	RekordObj               models.RekordV001Schema
	fetchedExternalEntities bool
}

const (
	APIVERSION = "0.0.1"
)

func (v V001Entry) APIVersion() string {
	return APIVERSION
}

func NewEntry() interface{} {
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

func (v *V001Entry) Unmarshal(e interface{}) error {
	cfg := mapstructure.DecoderConfig{
		DecodeHook: Base64StringtoByteArray(),
		Result:     &v.RekordObj,
	}

	dec, err := mapstructure.NewDecoder(&cfg)
	if err != nil {
		return fmt.Errorf("error initializing decoder: %w", err)
	}

	rekord := e.(*models.Rekord)
	if err := dec.Decode(rekord.Spec); err != nil {
		return err
	}
	return v.RekordObj.Validate(nil) //TODO: implement custom field validation for pki content
}

func (v V001Entry) HasExternalEntities() bool {
	return v.fetchedExternalEntities
}

// fileOrURLReadCloser caller is responsible for closing ReadCloser returned from method
func fileOrURLReader(url string, content []byte, ctx context.Context, checkGZIP bool) (io.ReadCloser, error) {
	var dataReader io.ReadCloser
	if url != "" {
		//TODO: set timeout here, SSL settings?
		client := &http.Client{}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("error received while fetching artifact: %v", resp.Status)
		}

		if checkGZIP {
			// read first 512 bytes to determine if content is gzip compressed
			bufReader := bufio.NewReaderSize(resp.Body, 512)
			ctBuf, err := bufReader.Peek(512)
			if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
				return nil, err
			}

			if http.DetectContentType(ctBuf) == "application/x-gzip" {
				dataReader, _ = gzip.NewReader(io.MultiReader(bufReader, resp.Body))
			} else {
				dataReader = ioutil.NopCloser(io.MultiReader(bufReader, resp.Body))
			}
		} else {
			dataReader = resp.Body
		}
	} else {
		dataReader = ioutil.NopCloser(bytes.NewReader(content))
	}
	return dataReader, nil
}

func (v *V001Entry) FetchExternalEntities(ctx context.Context) error {
	if v.fetchedExternalEntities {
		return nil
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	sigR, sigW := io.Pipe()
	defer hashR.Close()
	defer sigR.Close()

	oldSHA := ""
	if v.RekordObj.Data.Hash != nil && v.RekordObj.Data.Hash.Value != nil {
		oldSHA = swag.StringValue(v.RekordObj.Data.Hash.Value)
	}

	g.Go(func() error {
		defer hashW.Close()
		defer sigW.Close()

		dataReadCloser, err := fileOrURLReader(v.RekordObj.Data.URL.String(), v.RekordObj.Data.Content, ctx, true)
		if err != nil {
			return err
		}
		defer dataReadCloser.Close()

		/* #nosec G110 */
		if _, err := io.Copy(io.MultiWriter(hashW, sigW), dataReadCloser); err != nil {
			return err
		}
		return nil
	})

	hashResult := make(chan string)

	g.Go(func() error {
		defer close(hashResult)
		hasher := sha256.New()

		if _, err := io.Copy(hasher, hashR); err != nil {
			return err
		}

		computedSHA := hex.EncodeToString(hasher.Sum(nil))
		if oldSHA != "" && computedSHA != oldSHA {
			return fmt.Errorf("SHA mismatch: %s != %s", computedSHA, oldSHA)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case hashResult <- computedSHA:
			return nil
		}
	})

	sigResult := make(chan *pki.PGPSignature)

	g.Go(func() error {
		defer close(sigResult)

		sigReadCloser, err := fileOrURLReader(v.RekordObj.Signature.URL.String(),
			v.RekordObj.Signature.Content, ctx, false)
		if err != nil {
			return err
		}
		defer sigReadCloser.Close()

		signature, err := pki.NewPGPSignature(sigReadCloser)
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case sigResult <- signature:
			return nil
		}
	})

	keyResult := make(chan *pki.PGPPublicKey)

	g.Go(func() error {
		defer close(keyResult)

		keyReadCloser, err := fileOrURLReader(v.RekordObj.Signature.PublicKey.URL.String(),
			v.RekordObj.Signature.PublicKey.Content, ctx, false)
		if err != nil {
			return err
		}
		defer keyReadCloser.Close()

		key, err := pki.NewPGPPublicKey(keyReadCloser)
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
		key, signature := <-keyResult, <-sigResult

		var err error
		if err = signature.Verify(sigR, key); err != nil {
			return err
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
		v.RekordObj.Data.Hash = &models.RekordV001SchemaDataHash{}
		v.RekordObj.Data.Hash.Algorithm = swag.String(models.RekordV001SchemaDataHashAlgorithmSha256)
		v.RekordObj.Data.Hash.Value = swag.String(computedSHA)
	}

	v.fetchedExternalEntities = true
	return nil
}

func (v *V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	if err := v.FetchExternalEntities(ctx); err != nil {
		return nil, err
	}

	// need to canonicalize signature & key content if provided
	if v.RekordObj.Signature.Content != nil {
		canonicalSig, err := pki.NewPGPSignature(bytes.NewReader(v.RekordObj.Signature.Content))
		if err != nil {
			return nil, err
		}
		v.RekordObj.Signature.Content, err = canonicalSig.CanonicalValue()
		if err != nil {
			return nil, err
		}
	}
	if v.RekordObj.Signature.PublicKey.Content != nil {
		canonicalKey, err := pki.NewPGPPublicKey(bytes.NewReader(v.RekordObj.Signature.PublicKey.Content))
		if err != nil {
			return nil, err
		}
		v.RekordObj.Signature.PublicKey.Content, err = canonicalKey.CanonicalValue()
		if err != nil {
			return nil, err
		}
	}

	bytes, err := v.RekordObj.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
