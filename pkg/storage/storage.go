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

package storage

import (
	"context"
	"errors"

	"github.com/sigstore/rekor/pkg/log"

	"github.com/spf13/viper"
	"gocloud.dev/blob"

	// Blank imports to register storage
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/memblob"
)

type AttestationStorage interface {
	StoreAttestation(ctx context.Context, key string, attestationType string, attestation []byte) error
	FetchAttestation(ctx context.Context, key string) ([]byte, string, error)
}

func NewAttestationStorage() (AttestationStorage, error) {
	if url := viper.GetString("attestation_storage_bucket"); url != "" {
		log.Logger.Infof("Configuring attestation storage at %s", url)
		bucket, err := blob.OpenBucket(context.Background(), url)
		if err != nil {
			return nil, err
		}
		return &Blob{
			bucket: bucket,
		}, nil
	}
	return nil, errors.New("no storage configured")
}

type Blob struct {
	bucket *blob.Bucket
}

func (b *Blob) StoreAttestation(ctx context.Context, key, attestationType string, attestation []byte) error {
	log.Logger.Infof("storing attestation of type %s at %s", attestationType, key)
	w, err := b.bucket.NewWriter(ctx, key, &blob.WriterOptions{
		ContentType: attestationType,
	})
	if err != nil {
		return err
	}
	if _, err := w.Write(attestation); err != nil {
		return err
	}
	return w.Close()
}

func (b *Blob) FetchAttestation(ctx context.Context, key string) ([]byte, string, error) {
	log.Logger.Infof("fetching attestation %s", key)
	exists, err := b.bucket.Exists(ctx, key)
	if err != nil {
		return nil, "", err
	}
	if !exists {
		return nil, "", nil
	}
	att, err := b.bucket.Attributes(ctx, key)
	if err != nil {
		return nil, "", err
	}

	data, err := b.bucket.ReadAll(ctx, key)
	if err != nil {
		return nil, "", err
	}
	return data, att.ContentType, nil
}
