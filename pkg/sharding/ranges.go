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

package sharding

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"sigs.k8s.io/yaml"
)

// Active and inactive shards
type LogRanges struct {
	// inactive shards are listed from oldest to newest
	inactive Ranges
	active   LogRange
}

type Ranges []LogRange

// LogRange represents a log or tree shard
type LogRange struct {
	TreeID        int64                `json:"treeID" yaml:"treeID"`
	TreeLength    int64                `json:"treeLength" yaml:"treeLength"`       // unused for active tree
	SigningConfig signer.SigningConfig `json:"signingConfig" yaml:"signingConfig"` // if unset, assume same as active tree
	Signer        signature.Signer
	PemPubKey     string // PEM-encoded PKIX public key
	LogID         string // Hex-encoded SHA256 digest of PKIX-encoded public key
}

func (l LogRange) String() string {
	return fmt.Sprintf("{ TreeID: %v, TreeLength: %v, SigningScheme: %v, PemPubKey: %v, LogID: %v }", l.TreeID, l.TreeLength, l.SigningConfig.SigningSchemeOrKeyPath, l.PemPubKey, l.LogID)
}

// NewLogRanges initializes the active and any inactive log shards
func NewLogRanges(ctx context.Context, logClient trillian.TrillianLogClient,
	inactiveShardsPath string, activeTreeID int64, signingConfig signer.SigningConfig) (LogRanges, error) {
	if activeTreeID == 0 {
		return LogRanges{}, errors.New("non-zero active tree ID required; please set the active tree ID via the `--trillian_log_server.tlog_id` flag")
	}

	// Initialize active shard
	activeLog, err := updateRange(ctx, logClient, LogRange{TreeID: activeTreeID, TreeLength: 0, SigningConfig: signingConfig}, true /*=active*/)
	if err != nil {
		return LogRanges{}, fmt.Errorf("creating range for active tree %d: %w", activeTreeID, err)
	}
	log.Logger.Infof("Active log: %s", activeLog.String())

	if inactiveShardsPath == "" {
		log.Logger.Info("No config file specified, no inactive shards")
		return LogRanges{active: activeLog}, nil
	}

	// Initialize inactive shards from inactive tree IDs
	ranges, err := logRangesFromPath(inactiveShardsPath)
	if err != nil {
		return LogRanges{}, fmt.Errorf("log ranges from path: %w", err)
	}
	for i, r := range ranges {
		// If no signing config is provided, use the active tree signing key
		if r.SigningConfig.IsUnset() {
			r.SigningConfig = signingConfig
		}
		r, err := updateRange(ctx, logClient, r, false /*=active*/)
		if err != nil {
			return LogRanges{}, fmt.Errorf("updating range for tree id %d: %w", r.TreeID, err)
		}
		ranges[i] = r
	}
	for i, r := range ranges {
		log.Logger.Infof("Inactive range %d: %s", i, r.String())
	}

	return LogRanges{
		inactive: ranges,
		active:   activeLog,
	}, nil
}

// logRangesFromPath unmarshals a shard config
func logRangesFromPath(path string) (Ranges, error) {
	var ranges Ranges
	contents, err := os.ReadFile(path)
	if err != nil {
		return Ranges{}, err
	}
	if string(contents) == "" {
		log.Logger.Info("Sharding config file contents empty, skipping init of logRange map")
		return Ranges{}, nil
	}
	if err := yaml.Unmarshal(contents, &ranges); err != nil {
		// Try to use JSON
		if jerr := json.Unmarshal(contents, &ranges); jerr == nil {
			return ranges, nil
		}
		return Ranges{}, err
	}
	return ranges, nil
}

// updateRange fills in any missing information about the range
func updateRange(ctx context.Context, logClient trillian.TrillianLogClient, r LogRange, active bool) (LogRange, error) {
	// If a tree length wasn't passed in or if the shard is inactive, fetch the tree size
	if r.TreeLength == 0 && !active {
		resp, err := logClient.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{LogId: r.TreeID})
		if err != nil {
			return LogRange{}, fmt.Errorf("getting signed log root for tree %d: %w", r.TreeID, err)
		}
		var root types.LogRootV1
		if err := root.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
			return LogRange{}, err
		}
		r.TreeLength = int64(root.TreeSize)
	}

	if r.SigningConfig.IsUnset() {
		return LogRange{}, fmt.Errorf("signing config not set, unable to initialize shard signer")
	}

	// Initialize shard signer
	s, err := signer.New(ctx, r.SigningConfig.SigningSchemeOrKeyPath, r.SigningConfig.FileSignerPassword,
		r.SigningConfig.TinkKEKURI, r.SigningConfig.TinkKeysetPath)
	if err != nil {
		return LogRange{}, err
	}
	r.Signer = s

	// Initialize public key
	pubKey, err := s.PublicKey(options.WithContext(ctx))
	if err != nil {
		return LogRange{}, err
	}
	pemPubKey, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return LogRange{}, err
	}
	r.PemPubKey = string(pemPubKey)

	// Initialize log ID from public key
	b, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return LogRange{}, err
	}
	pubkeyHashBytes := sha256.Sum256(b)
	r.LogID = hex.EncodeToString(pubkeyHashBytes[:])

	return r, nil
}

func (l *LogRanges) ResolveVirtualIndex(index int) (int64, int64) {
	indexLeft := index
	for _, l := range l.inactive {
		if indexLeft < int(l.TreeLength) {
			return l.TreeID, int64(indexLeft)
		}
		indexLeft -= int(l.TreeLength)
	}

	// If index not found in inactive trees, return the active tree
	return l.active.TreeID, int64(indexLeft)
}

func (l *LogRanges) NoInactive() bool {
	return l.inactive == nil
}

// AllShards returns all shards, starting with the active shard and then the inactive shards
func (l *LogRanges) AllShards() []int64 {
	shards := []int64{l.GetActive().TreeID}
	for _, in := range l.GetInactive() {
		shards = append(shards, in.TreeID)
	}
	return shards
}

// TotalInactiveLength returns the total length across all inactive shards;
// we don't know the length of the active shard.
func (l *LogRanges) TotalInactiveLength() int64 {
	var total int64
	for _, r := range l.inactive {
		total += r.TreeLength
	}
	return total
}

// GetLogRangeByTreeID returns the active or inactive
// shard with the given tree ID
func (l *LogRanges) GetLogRangeByTreeID(treeID int64) (LogRange, error) {
	if l.active.TreeID == treeID {
		return l.active, nil
	}
	for _, i := range l.inactive {
		if i.TreeID == treeID {
			return i, nil
		}
	}
	return LogRange{}, fmt.Errorf("no log range found for tree ID %d", treeID)
}

// GetInactive returns all inactive shards
func (l *LogRanges) GetInactive() []LogRange {
	return l.inactive
}

// GetActive returns the cative shard
func (l *LogRanges) GetActive() LogRange {
	return l.active
}

func (l *LogRanges) String() string {
	ranges := []string{}
	for _, r := range l.inactive {
		ranges = append(ranges, fmt.Sprintf("%d=%d", r.TreeID, r.TreeLength))
	}
	ranges = append(ranges, fmt.Sprintf("active=%d", l.active.TreeID))
	return strings.Join(ranges, ",")
}

// PublicKey returns the associated public key for the given Tree ID
// and returns the active public key by default
func (l *LogRanges) PublicKey(treeID string) (string, error) {
	// if no tree ID is specified, assume the active tree
	if treeID == "" {
		return l.active.PemPubKey, nil
	}
	tid, err := strconv.Atoi(treeID)
	if err != nil {
		return "", err
	}

	if tid == int(l.GetActive().TreeID) {
		return l.active.PemPubKey, nil
	}

	for _, i := range l.inactive {
		if int(i.TreeID) == tid {
			return i.PemPubKey, nil
		}
	}
	return "", fmt.Errorf("%d is not a valid tree ID and doesn't have an associated public key", tid)
}
