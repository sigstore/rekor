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

	"github.com/projectrekor/rekor/pkg/pki"
	"golang.org/x/sync/errgroup"
)

// RekorEntry is the API request.
type RekorEntry struct {
	Data      []byte
	URL       string
	RekorLeaf `json:"-"`
}

// RekorLeaf is the type we store in the log.
type RekorLeaf struct {
	SHA       string
	Signature []byte
	PublicKey []byte
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
	cLeaf.Signature, err = r.sigObject.CanonicalValue()
	if err != nil {
		return nil, err
	}
	cLeaf.PublicKey, err = r.keyObject.CanonicalValue()
	if err != nil {
		return nil, err
	}
	return json.Marshal(cLeaf)
}

func ParseRekorLeaf(r io.Reader) (*RekorLeaf, error) {
	var l RekorLeaf
	dec := json.NewDecoder(r)
	if err := dec.Decode(&l); err != nil && err != io.EOF {
		return nil, err
	}

	if err := l.ParseKeys(); err != nil {
		return nil, err
	}
	return &l, nil
}

func (l *RekorLeaf) ParseKeys() error {
	// validate fields
	if l.SHA != "" {
		if _, err := hex.DecodeString(l.SHA); err != nil || len(l.SHA) != 64 {
			return fmt.Errorf("Invalid SHA hash provided")
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

func ParseRekorEntry(r io.Reader, leaf *RekorLeaf) (*RekorEntry, error) {
	var e RekorEntry
	dec := json.NewDecoder(r)
	if err := dec.Decode(&e); err != nil && err != io.EOF {
		return nil, err
	}
	//decode above should not have included the previously parsed & validated leaf, so copy it in
	e.RekorLeaf = *leaf

	if e.Data == nil && e.URL == "" {
		return nil, errors.New("one of Contents or ContentsRef must be set")
	}

	if e.URL != "" && e.SHA == "" {
		return nil, errors.New("SHA hash must be specified if URL is set")
	}

	return &e, nil
}

func (r *RekorEntry) Load(ctx context.Context) error {

	hashR, hashW := io.Pipe()
	sigR, sigW := io.Pipe()

	var dataReader io.Reader
	if r.URL != "" {
		//TODO: set timeout here, SSL settings?
		resp, err := http.DefaultClient.Get(r.URL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		// read first 512 bytes to determine if content is gzip compressed
		bufReader := bufio.NewReaderSize(resp.Body, 512)
		ctBuf, err := bufReader.Peek(512)
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return err
		}

		if "application/x+gzip" == http.DetectContentType(ctBuf) {
			dataReader, _ = gzip.NewReader(io.MultiReader(bufReader, resp.Body))
		} else {
			dataReader = io.MultiReader(bufReader, resp.Body)
		}
	} else {
		dataReader = bytes.NewReader(r.Data)
	}

	if err := r.ParseKeys(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

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
		defer hashR.Close()
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
		defer sigR.Close()

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
