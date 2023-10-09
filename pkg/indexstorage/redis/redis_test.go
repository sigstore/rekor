// Copyright 2023 The Sigstore Authors.
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

package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/go-redis/redismock/v9"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/goleak"
)

func TestLookupIndices(t *testing.T) {
	key := "87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"
	value := []string{"1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"}
	redisClient, mock := redismock.NewClientMock()
	mock.Regexp().ExpectLRange(key, 0, -1).SetVal(value)

	isp := IndexStorageProvider{redisClient}

	indices, err := isp.LookupIndices(context.Background(), key)
	if err != nil {
		t.Error(err)
	}

	less := func(a, b string) bool { return a < b }
	if cmp.Diff(value, indices, cmpopts.SortSlices(less)) != "" {
		t.Errorf("expected %s, got %s", value, indices)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	mock.ClearExpect()
	errRedis := errors.New("redis error")
	mock.Regexp().ExpectLRange(key, 0, -1).SetErr(errRedis)
	if _, err := isp.LookupIndices(context.Background(), key); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestWriteIndex(t *testing.T) {
	key := "87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"
	value := []string{"1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"}
	redisClient, mock := redismock.NewClientMock()
	mock.Regexp().ExpectLPush(key, value).SetVal(1)

	isp := IndexStorageProvider{redisClient}
	if err := isp.WriteIndex(context.Background(), key, value[0]); err != nil {
		t.Error(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	mock.ClearExpect()
	errRedis := errors.New("redis error")
	mock.Regexp().ExpectLPush(key, value).SetErr(errRedis)
	if err := isp.WriteIndex(context.Background(), key, value[0]); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestUninitializedClient(t *testing.T) {
	// this is not initialized with a real Redis client
	isp := IndexStorageProvider{}
	if _, err := isp.LookupIndices(context.Background(), "key"); err == nil {
		t.Error("unexpected success")
	}
	if err := isp.WriteIndex(context.Background(), "key", "value"); err == nil {
		t.Error("unexpected success")
	}
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
