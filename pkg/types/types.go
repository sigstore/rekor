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

package types

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"

	"github.com/projectrekor/rekor/pkg/generated/models"
	"github.com/projectrekor/rekor/pkg/pki"
	"golang.org/x/sync/errgroup"
)

type TypeImpl interface {
	Kind() string
	UnmarshalEntry(pe interface{}) (*EntryImpl, error)
}

type EntryImpl interface {
	APIVersion() string
	CanonicalLeaf() ([]byte, error)
	FetchExternalEntities() error
	HasExternalEntities() bool
	Unmarshal(e interface{}) error
}

var typeMap = map[string]TypeImpl{}

func init() {
	// add new type objects here
	typeArray := []TypeImpl{
		RekordType{},
	}

	for _, t := range typeArray {
		if _, found := typeMap[t.Kind()]; found {
			panic(fmt.Errorf("entry in typeMap for %v already exists", t.Kind()))
		}
		typeMap[t.Kind()] = t
	}
}

func NewEntry(pe models.ProposedEntry) (EntryImpl, error) {
	if t, found := typeMap[pe.Kind()]; found {
		et, err := t.UnmarshalEntry(pe)
		if err != nil {
			return nil, err
		}
		return *et, nil
	}
	return nil, fmt.Errorf("could not create entry for kind '%v'", pe.Kind())
}

// RekorEntry is the API request.
type RekorEntry struct {
	Data []byte `json:"Data,omitempty"`
	URL  string `json:"URL,omitempty"`
	RekorLeaf
}

// RekorLeaf is the type we store in the log.
type RekorLeaf struct {
	SHA       string `json:"SHA,omitempty"`
	Signature []byte `json:"Signature"`
	PublicKey []byte `json:"PublicKey"`
	keyObject pki.PublicKey
	sigObject pki.Signature
}

// MarshalJSON Ensures that the canonicalized versions of public keys & signatures are stored in tLOG
func (r *RekorLeaf) MarshalJSON() ([]byte, error) {
	//create an identical type but due to reflection will not recursively enter this marshaller
	type canonicalLeaf struct {
		RekorLeaf
	}
	var cLeaf canonicalLeaf
	cLeaf.SHA = r.SHA

	var err error
	if reflect.ValueOf(r.sigObject).IsNil() {
		return nil, errors.New("signature has not been initialized")
	}
	cLeaf.Signature, err = r.sigObject.CanonicalValue()
	if err != nil {
		return nil, err
	}

	if reflect.ValueOf(r.keyObject).IsNil() {
		return nil, errors.New("public key has not been initialized")
	}
	cLeaf.PublicKey, err = r.keyObject.CanonicalValue()
	if err != nil {
		return nil, err
	}
	return json.Marshal(cLeaf)
}

func ParseRekorLeaf(r io.Reader) (RekorLeaf, error) {
	var l RekorLeaf
	dec := json.NewDecoder(r)
	if err := dec.Decode(&l); err != nil && err != io.EOF {
		return RekorLeaf{}, err
	}

	if err := l.ValidateLeaf(); err != nil {
		return RekorLeaf{}, err
	}
	return l, nil
}

func (l *RekorLeaf) ValidateLeaf() error {
	// validate fields
	if l.SHA != "" {
		if _, err := hex.DecodeString(l.SHA); err != nil || len(l.SHA) != 64 {
			return fmt.Errorf("invalid SHA hash provided")
		}
	}

	//TODO: make this create the appropriate signature & key objects based on
	//      the content in the proposed leaf rather than being hardcoded to PGP
	var err error
	// check if this is an actual signature
	l.sigObject, err = pki.NewPGPSignature(bytes.NewReader(l.Signature))
	if err != nil {
		return err
	}

	// check if this is an actual public key
	l.keyObject, err = pki.NewPGPPublicKey(bytes.NewReader(l.PublicKey))
	if err != nil {
		return err
	}
	return nil
}

func ParseRekorEntry(r io.Reader, leaf RekorLeaf) (*RekorEntry, error) {
	if err := leaf.ValidateLeaf(); err != nil {
		return nil, err
	}

	var e RekorEntry
	dec := json.NewDecoder(r)
	if err := dec.Decode(&e); err != nil && err != io.EOF {
		return nil, err
	}

	//decode above should not have included the previously parsed & validated leaf, so copy it in
	e.RekorLeaf = leaf

	if e.Data == nil && e.URL == "" {
		return nil, errors.New("one of Data or URL must be set")
	}

	if e.URL != "" {
		if _, err := url.ParseRequestURI(e.URL); err != nil {
			return nil, fmt.Errorf("url parsing failed: %w", err)
		}

		if e.SHA == "" {
			return nil, errors.New("SHA hash must be specified if URL is set")
		}
	}

	return &e, nil
}

func (r *RekorEntry) Load(ctx context.Context) error {

	if err := r.ValidateLeaf(); err != nil {
		return err
	}

	var dataReader io.Reader
	if r.URL != "" {
		//TODO: set timeout here, SSL settings?
		resp, err := http.DefaultClient.Get(r.URL)
		if err != nil {
			return err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("error received while fetching artifact: %v", resp.Status)
		}
		defer resp.Body.Close()

		// read first 512 bytes to determine if content is gzip compressed
		bufReader := bufio.NewReaderSize(resp.Body, 512)
		ctBuf, err := bufReader.Peek(512)
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return err
		}

		if http.DetectContentType(ctBuf) == "application/x-gzip" {
			dataReader, _ = gzip.NewReader(io.MultiReader(bufReader, resp.Body))
		} else {
			dataReader = io.MultiReader(bufReader, resp.Body)
		}
	} else {
		dataReader = bytes.NewReader(r.Data)
	}

	g, ctx := errgroup.WithContext(ctx)

	hashR, hashW := io.Pipe()
	sigR, sigW := io.Pipe()
	defer hashR.Close()
	defer sigR.Close()

	g.Go(func() error {
		defer hashW.Close()
		defer sigW.Close()

		/* #nosec G110 */
		if _, err := io.Copy(io.MultiWriter(hashW, sigW), dataReader); err != nil {
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
		if r.SHA != "" && computedSHA != r.SHA {
			return fmt.Errorf("SHA mismatch: %s != %s", computedSHA, r.SHA)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case hashResult <- computedSHA:
			return nil
		}
	})

	g.Go(func() error {
		if err := r.sigObject.Verify(sigR, r.keyObject); err != nil {
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
	if r.SHA == "" {
		r.SHA = computedSHA
	}

	return nil
}
