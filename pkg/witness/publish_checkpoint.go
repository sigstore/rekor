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
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/grpc/codes"
)

// CheckpointPublisher is a long-running job to periodically publish signed checkpoints to etc.d
type CheckpointPublisher struct {
	ctx context.Context
	// logClient is the client for Trillian
	logClient trillian.TrillianLogClient
	// treeID is used to construct the origin and configure the Trillian client
	treeID int64
	// hostname is used to construct the origin ("hostname - treeID")
	hostname string
	// signer signs the checkpoint
	signer signature.Signer
	// publishFreq is how often a new checkpoint is published to Rekor, in minutes
	checkpointFreq uint
	// redisClient to upload signed checkpoints
	redisClient *redis.Client
	// reqCounter tracks successes and failures for publishing
	reqCounter *prometheus.CounterVec
}

// Constant values used with metrics
const (
	Success = iota
	SuccessObtainLock
	GetCheckpoint
	UnmarshalCheckpoint
	SignCheckpoint
	RedisFailure
	RedisLatestFailure
)

// NewCheckpointPublisher creates a CheckpointPublisher to write stable checkpoints to Redis
func NewCheckpointPublisher(ctx context.Context,
	logClient trillian.TrillianLogClient,
	treeID int64,
	hostname string,
	signer signature.Signer,
	redisClient *redis.Client,
	checkpointFreq uint,
	reqCounter *prometheus.CounterVec) CheckpointPublisher {
	return CheckpointPublisher{ctx: ctx, logClient: logClient, treeID: treeID, hostname: hostname,
		signer: signer, checkpointFreq: checkpointFreq, redisClient: redisClient, reqCounter: reqCounter}
}

// StartPublisher creates a long-running task that publishes the latest checkpoint every X minutes
// Writing to Redis is best effort. Failure will be detected either through metrics or by witnesses
// or Verifiers monitoring for fresh checkpoints. Failure can occur after a lock is obtained but
// before publishing the latest checkpoint. If this occurs due to a sporadic failure, this simply
// means that a witness will not see a fresh checkpoint for an additional period.
func (c *CheckpointPublisher) StartPublisher() {
	tc := trillianclient.NewTrillianClient(context.Background(), c.logClient, c.treeID)
	sTreeID := strconv.FormatInt(c.treeID, 10)

	// publish on startup to ensure a checkpoint is available the first time Rekor starts up
	c.publish(&tc, sTreeID)

	ticker := time.NewTicker(time.Duration(c.checkpointFreq) * time.Minute)
	go func() {
		for {
			<-ticker.C
			c.publish(&tc, sTreeID)
		}
	}()
}

// publish publishes the latest checkpoint to Redis once
func (c *CheckpointPublisher) publish(tc *trillianclient.TrillianClient, sTreeID string) {
	// get latest checkpoint
	resp := tc.GetLatest(0)
	if resp.Status != codes.OK {
		c.reqCounter.With(
			map[string]string{
				"shard": sTreeID,
				"code":  strconv.Itoa(GetCheckpoint),
			}).Inc()
		log.Logger.Errorf("error getting latest checkpoint to publish: %v", resp.Status)
		return
	}

	// unmarshal checkpoint
	root := &types.LogRootV1{}
	if err := root.UnmarshalBinary(resp.GetLatestResult.SignedLogRoot.LogRoot); err != nil {
		c.reqCounter.With(
			map[string]string{
				"shard": sTreeID,
				"code":  strconv.Itoa(UnmarshalCheckpoint),
			}).Inc()
		log.Logger.Errorf("error unmarshalling latest checkpoint to publish: %v", err)
		return
	}

	// sign checkpoint with Rekor private key
	checkpoint, err := util.CreateAndSignCheckpoint(context.Background(), c.hostname, c.treeID, root, c.signer)
	if err != nil {
		c.reqCounter.With(
			map[string]string{
				"shard": sTreeID,
				"code":  strconv.Itoa(SignCheckpoint),
			}).Inc()
		log.Logger.Errorf("error signing checkpoint to publish: %v", err)
		return
	}

	// encode checkpoint as hex to write to redis
	hexCP := hex.EncodeToString(checkpoint)

	// write checkpoint to Redis if key does not yet exist
	// this prevents multiple instances of Rekor from writing different checkpoints in the same time window
	ts := time.Now().Truncate(time.Duration(c.checkpointFreq) * time.Minute).UnixNano()
	// key is treeID/timestamp, where timestamp is rounded down to the nearest X minutes
	key := fmt.Sprintf("%d/%d", c.treeID, ts)
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	// return value ignored, which is whether or not the entry was set
	// no error is thrown if the key already exists
	successNX, err := c.redisClient.SetNX(ctx, key, hexCP, 0).Result()
	if err != nil {
		c.reqCounter.With(
			map[string]string{
				"shard": sTreeID,
				"code":  strconv.Itoa(RedisFailure),
			}).Inc()
		log.Logger.Errorf("error with client publishing checkpoint: %v", err)
		return
	}
	// if the key was not set, then the key already exists for this time period
	if !successNX {
		return
	}

	// successful obtaining of lock for time period
	c.reqCounter.With(
		map[string]string{
			"shard": sTreeID,
			"code":  strconv.Itoa(SuccessObtainLock),
		}).Inc()

	// on successfully obtaining the "lock" for the time window, update latest checkpoint
	latestKey := fmt.Sprintf("%d/latest", c.treeID)
	latestCtx, latestCancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer latestCancel()

	// return value ignored, which is whether or not the entry was set
	// no error is thrown if the key already exists
	if _, err = c.redisClient.Set(latestCtx, latestKey, hexCP, 0).Result(); err != nil {
		c.reqCounter.With(
			map[string]string{
				"shard": sTreeID,
				"code":  strconv.Itoa(RedisLatestFailure),
			}).Inc()
		log.Logger.Errorf("error with client publishing latest checkpoint: %v", err)
		return
	}

	// successful publish
	c.reqCounter.With(
		map[string]string{
			"shard": sTreeID,
			"code":  strconv.Itoa(Success),
		}).Inc()
}
