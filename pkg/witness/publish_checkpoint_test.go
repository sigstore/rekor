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

package witness

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sigstore/rekor/pkg/witness/mockclient"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestPublishCheckpoint(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	root := &types.LogRootV1{TreeSize: 10, RootHash: []byte{1}, TimestampNanos: 123, Revision: 0}
	mRoot, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("error marshalling log root: %v", err)
	}

	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{
		LogId:         int64(treeID),
		FirstTreeSize: 0,
	}).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: mRoot}}, nil)

	redisClient, mock := redismock.NewClientMock()
	ts := time.Now().Truncate(time.Duration(freq) * time.Minute).UnixNano()
	mock.Regexp().ExpectSetNX(fmt.Sprintf("%d/%d", treeID, ts), "[0-9a-fA-F]+", 0).SetVal(true)
	mock.Regexp().ExpectSet(fmt.Sprintf("%d/latest", treeID), "[0-9a-fA-F]+", 0).SetVal("OK")

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	if res := testutil.CollectAndCount(counter); res != 2 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(Success))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(SuccessObtainLock))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}

func TestPublishCheckpointMultiple(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	root := &types.LogRootV1{TreeSize: 10, RootHash: []byte{1}, TimestampNanos: 123, Revision: 0}
	mRoot, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("error marshalling log root: %v", err)
	}

	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), &trillian.GetLatestSignedLogRootRequest{
		LogId:         int64(treeID),
		FirstTreeSize: 0,
	}).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: mRoot}}, nil).MaxTimes(2)

	redisClient, mock := redismock.NewClientMock()
	ts := time.Now().Truncate(time.Duration(freq) * time.Minute).UnixNano()
	mock.Regexp().ExpectSetNX(fmt.Sprintf("%d/%d", treeID, ts), "[0-9a-fA-F]+", 0).SetVal(true)
	mock.Regexp().ExpectSet(fmt.Sprintf("%d/latest", treeID), "[0-9a-fA-F]+", 0).SetVal("OK")

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	redisClientEx, mockEx := redismock.NewClientMock()
	mockEx.Regexp().ExpectSetNX(fmt.Sprintf("%d/%d", treeID, ts), "[0-9a-fA-F]+", 0).SetVal(false)
	publisherEx := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClientEx, uint(freq), counter)
	publisherEx.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
	if err := mockEx.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	// only publishes once
	if res := testutil.CollectAndCount(counter); res != 2 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(Success))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(SuccessObtainLock))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}

func TestPublishCheckpointTrillianError(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// return error
	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(nil, errors.New("error: LatestSLR"))

	redisClient, _ := redismock.NewClientMock()

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	if res := testutil.CollectAndCount(counter); res != 1 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(GetCheckpoint))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}

func TestPublishCheckpointInvalidTrillianResponse(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// set no log root in response
	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: []byte{}}}, nil)

	redisClient, _ := redismock.NewClientMock()

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	if res := testutil.CollectAndCount(counter); res != 1 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(UnmarshalCheckpoint))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}

func TestPublishCheckpointRedisFailure(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	root := &types.LogRootV1{TreeSize: 10, RootHash: []byte{1}, TimestampNanos: 123, Revision: 0}
	mRoot, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("error marshalling log root: %v", err)
	}

	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: mRoot}}, nil)

	redisClient, mock := redismock.NewClientMock()
	// error on first redis call
	mock.Regexp().ExpectSetNX(".+", "[0-9a-fA-F]+", 0).SetErr(errors.New("redis error"))

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	if res := testutil.CollectAndCount(counter); res != 1 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(RedisFailure))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}

func TestPublishCheckpointRedisLatestFailure(t *testing.T) {
	treeID := 1234
	hostname := "rekor-test"
	freq := 1
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rekor_checkpoint_publish",
		Help: "Checkpoint publishing by shard and code",
	}, []string{"shard", "code"})
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := signature.LoadSigner(priv, crypto.SHA256)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	root := &types.LogRootV1{TreeSize: 10, RootHash: []byte{1}, TimestampNanos: 123, Revision: 0}
	mRoot, err := root.MarshalBinary()
	if err != nil {
		t.Fatalf("error marshalling log root: %v", err)
	}

	mockTrillianLogClient := mockclient.NewMockTrillianLogClient(ctrl)
	mockTrillianLogClient.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).
		Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: mRoot}}, nil)

	redisClient, mock := redismock.NewClientMock()
	mock.Regexp().ExpectSetNX(".+", "[0-9a-fA-F]+", 0).SetVal(true)
	// error on second redis call
	mock.Regexp().ExpectSet(".*", "[0-9a-fA-F]+", 0).SetErr(errors.New("error"))

	publisher := NewCheckpointPublisher(context.Background(), mockTrillianLogClient, int64(treeID), hostname, signer, redisClient, uint(freq), counter)
	publisher.StartPublisher()

	// wait for initial publish
	time.Sleep(1 * time.Second)

	// two metrics, one success for initial redis and one failure for latest
	if res := testutil.CollectAndCount(counter); res != 2 {
		t.Fatalf("unexpected number of metrics: %d", res)
	}
	if res := testutil.ToFloat64(counter.WithLabelValues(fmt.Sprint(treeID), fmt.Sprint(RedisLatestFailure))); res != 1.0 {
		t.Fatalf("unexpected number of metrics: %2f", res)
	}
}
