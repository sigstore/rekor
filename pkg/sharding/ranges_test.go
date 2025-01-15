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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian/testonly"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/google/trillian"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

func TestNewLogRanges(t *testing.T) {
	keyPath, ecdsaSigner, pemPubKey, logID := initializeSigner(t)
	sc := signer.SigningConfig{SigningSchemeOrKeyPath: keyPath}

	// inactive shard with different key
	keyPathI, ecdsaSignerI, pemPubKeyI, logIDI := initializeSigner(t)
	scI := signer.SigningConfig{SigningSchemeOrKeyPath: keyPathI}

	contents := fmt.Sprintf(`
- treeID: 0001
  treeLength: 3
- treeID: 0002
  treeLength: 4
- treeID: 0003
  treeLength: 5
  signingConfig:
    signingSchemeOrKeyPath: '%s'`, keyPathI)
	fmt.Println(contents)
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	treeID := int64(45)
	expected := LogRanges{
		inactive: []LogRange{
			// two inactive shards without signing config
			// inherit config from active shard
			{
				TreeID:        1,
				TreeLength:    3,
				SigningConfig: sc,
				Signer:        ecdsaSigner,
				PemPubKey:     pemPubKey,
				LogID:         logID,
			}, {
				TreeID:        2,
				TreeLength:    4,
				SigningConfig: sc,
				Signer:        ecdsaSigner,
				PemPubKey:     pemPubKey,
				LogID:         logID,
			}, {
				// inactive shard with custom signing config
				TreeID:        3,
				TreeLength:    5,
				SigningConfig: scI,
				Signer:        ecdsaSignerI,
				PemPubKey:     pemPubKeyI,
				LogID:         logIDI,
			},
		},
		active: LogRange{
			TreeID:        45,
			TreeLength:    0, // unset
			SigningConfig: sc,
			Signer:        ecdsaSigner,
			PemPubKey:     pemPubKey,
			LogID:         logID,
		},
	}
	ctx := context.Background()
	tc := trillian.NewTrillianLogClient(&grpc.ClientConn{})
	got, err := NewLogRanges(ctx, tc, file, treeID, sc)
	if err != nil {
		t.Fatal(err)
	}
	if expected.GetActive().TreeID != got.GetActive().TreeID {
		t.Fatalf("expected tree id %d got %d", expected.GetActive().TreeID, got.GetActive().TreeID)
	}
	for i, expected := range expected.GetInactive() {
		got := got.GetInactive()[i]
		logRangeEqual(t, expected, got)
	}

	// Failure: Tree ID = 0
	_, err = NewLogRanges(ctx, tc, file, 0, sc)
	if err == nil || !strings.Contains(err.Error(), "non-zero active tree ID required") {
		t.Fatal("expected error initializing log ranges with 0 tree ID")
	}
}

func TestLogRanges_ResolveVirtualIndex(t *testing.T) {
	lrs := LogRanges{
		inactive: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100},
		},
		active: LogRange{TreeID: 4},
	}

	for _, tt := range []struct {
		Index      int
		WantTreeID int64
		WantIndex  int64
	}{
		{
			Index:      3,
			WantTreeID: 1, WantIndex: 3,
		},
		// This is the first (0th) entry in the next tree
		{
			Index:      17,
			WantTreeID: 2, WantIndex: 0,
		},
		// Overflow
		{
			Index:      3000,
			WantTreeID: 4, WantIndex: 2882,
		},
	} {
		tree, index := lrs.ResolveVirtualIndex(tt.Index)
		if tree != tt.WantTreeID {
			t.Errorf("LogRanges.ResolveVirtualIndex() tree = %v, want %v", tree, tt.WantTreeID)
		}
		if index != tt.WantIndex {
			t.Errorf("LogRanges.ResolveVirtualIndex() index = %v, want %v", index, tt.WantIndex)
		}
	}
}

func TestLogRanges_GetLogRangeByTreeID(t *testing.T) {
	lrs := LogRanges{
		inactive: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100},
		},
		active: LogRange{TreeID: 4},
	}

	for _, tt := range []struct {
		treeID       int64
		wantLogRange LogRange
		wantErr      bool
	}{
		// Active shard
		{
			treeID:       4,
			wantLogRange: LogRange{TreeID: 4},
			wantErr:      false,
		},
		// One of the inactive shards
		{
			treeID:       2,
			wantLogRange: LogRange{TreeID: 2, TreeLength: 1},
			wantErr:      false,
		},
		// Missing shard
		{
			treeID:       100,
			wantLogRange: LogRange{},
			wantErr:      true,
		},
	} {
		got, err := lrs.GetLogRangeByTreeID(tt.treeID)
		if (err != nil) != tt.wantErr {
			t.Errorf("GetLogRangeByTreeID() error = %v, wantErr %v", err, tt.wantErr)
			return
		}
		if !reflect.DeepEqual(tt.wantLogRange, got) {
			t.Fatalf("log range did not match: %v, %v", tt.wantLogRange, got)
		}
	}
}

func TestLogRanges_PublicKey(t *testing.T) {
	ranges := LogRanges{
		active: LogRange{TreeID: 45, PemPubKey: "activekey"},
		inactive: []LogRange{
			{
				TreeID:     10,
				TreeLength: 10,
				PemPubKey:  "sharding10",
			}, {
				TreeID:     20,
				TreeLength: 20,
				PemPubKey:  "sharding20",
			},
		},
	}
	tests := []struct {
		description    string
		treeID         string
		expectedPubKey string
		shouldErr      bool
	}{
		{
			description:    "empty tree ID",
			expectedPubKey: "activekey",
		}, {
			description:    "tree id with decoded public key",
			treeID:         "10",
			expectedPubKey: "sharding10",
		}, {
			description:    "tree id without decoded public key",
			treeID:         "20",
			expectedPubKey: "sharding20",
		}, {
			description: "invalid tree id",
			treeID:      "34",
			shouldErr:   true,
		}, {
			description:    "pass in active tree id",
			treeID:         "45",
			expectedPubKey: "activekey",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			got, err := ranges.PublicKey(test.treeID)
			if err != nil && !test.shouldErr {
				t.Fatal(err)
			}
			if test.shouldErr {
				return
			}
			if got != test.expectedPubKey {
				t.Fatalf("got %s doesn't match expected %s", got, test.expectedPubKey)
			}
		})
	}
}

func TestLogRanges_String(t *testing.T) {
	type fields struct {
		inactive Ranges
		active   LogRange
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "empty",
			fields: fields{
				inactive: Ranges{},
				active:   LogRange{},
			},
			want: "active=0",
		},
		{
			name: "one",
			fields: fields{
				inactive: Ranges{
					{
						TreeID:     1,
						TreeLength: 2,
					},
				},
				active: LogRange{TreeID: 3},
			},
			want: "1=2,active=3",
		},
		{
			name: "two",
			fields: fields{
				inactive: Ranges{
					{
						TreeID:     1,
						TreeLength: 2,
					},
					{
						TreeID:     2,
						TreeLength: 3,
					},
				},
				active: LogRange{TreeID: 4},
			},
			want: "1=2,2=3,active=4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LogRanges{
				inactive: tt.fields.inactive,
				active:   tt.fields.active,
			}
			if got := l.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogRanges_TotalInactiveLength(t *testing.T) {
	type fields struct {
		inactive Ranges
		active   LogRange
	}
	tests := []struct {
		name   string
		fields fields
		want   int64
	}{
		{
			name: "empty",
			fields: fields{
				inactive: Ranges{},
				active:   LogRange{},
			},
			want: 0,
		},
		{
			name: "one",
			fields: fields{
				inactive: Ranges{
					{
						TreeID:     1,
						TreeLength: 2,
					},
				},
				active: LogRange{TreeID: 3},
			},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LogRanges{
				inactive: tt.fields.inactive,
				active:   tt.fields.active,
			}
			if got := l.TotalInactiveLength(); got != tt.want {
				t.Errorf("TotalInactiveLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogRanges_AllShards(t *testing.T) {
	type fields struct {
		inactive Ranges
		active   LogRange
	}
	tests := []struct {
		name   string
		fields fields
		want   []int64
	}{
		{
			name: "empty",
			fields: fields{
				inactive: Ranges{},
				active:   LogRange{},
			},
			want: []int64{0},
		},
		{
			name: "one",
			fields: fields{
				inactive: Ranges{
					{
						TreeID:     1,
						TreeLength: 2,
					},
				},
				active: LogRange{TreeID: 3},
			},
			want: []int64{3, 1},
		},
		{
			name: "two",
			fields: fields{
				inactive: Ranges{
					{
						TreeID:     1,
						TreeLength: 2,
					},
					{
						TreeID:     2,
						TreeLength: 3,
					},
				},
				active: LogRange{TreeID: 4},
			},
			want: []int64{4, 1, 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &LogRanges{
				inactive: tt.fields.inactive,
				active:   tt.fields.active,
			}
			if got := l.AllShards(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AllShards() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogRanges_ActiveAndInactive(t *testing.T) {
	active := LogRange{
		TreeID: 1,
	}
	inactive := Ranges{
		{
			TreeID:     2,
			TreeLength: 123,
		},
		{
			TreeID:     3,
			TreeLength: 456,
		},
	}
	lr := LogRanges{
		active:   active,
		inactive: inactive,
	}
	if lr.NoInactive() {
		t.Fatalf("expected inactive shards, got no shards")
	}
	if !reflect.DeepEqual(active, lr.active) {
		t.Fatalf("expected active shards to be equal")
	}
	if !reflect.DeepEqual(inactive, lr.inactive) {
		t.Fatalf("expected inactive shards to be equal")
	}
}

func TestLogRangesFromPath(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name            string
		args            args
		want            Ranges
		content         string
		wantJSON        bool
		wantYaml        bool
		wantInvalidJSON bool
		wantErr         bool
	}{
		{
			name: "empty",
			args: args{
				path: "",
			},
			want:    Ranges{},
			wantErr: true,
		},
		{
			name: "empty file",
			args: args{
				path: "one",
			},
			want:    Ranges{},
			wantErr: false,
		},
		{
			name: "valid json",
			args: args{
				path: "one",
			},
			want: Ranges{
				{
					TreeID:     1,
					TreeLength: 2,
				},
			},
			wantJSON: true,
			wantErr:  false,
		},
		{
			name: "valid yaml",
			args: args{
				path: "one",
			},
			want: Ranges{
				{
					TreeID:     1,
					TreeLength: 2,
				},
			},
			wantYaml: true,
			wantErr:  false,
		},
		{
			name: "invalid json",
			args: args{
				path: "one",
			},
			want:            Ranges{},
			wantInvalidJSON: true,
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.path != "" {
				f, err := os.CreateTemp("", tt.args.path)
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				switch {
				case tt.wantJSON:
					if err := json.NewEncoder(f).Encode(tt.want); err != nil {
						t.Fatalf("Failed to encode json: %v", err)
					}
				case tt.wantYaml:
					if err := yaml.NewEncoder(f).Encode(tt.want); err != nil {
						t.Fatalf("Failed to encode yaml: %v", err)
					}
				case tt.wantInvalidJSON:
					if _, err := f.WriteString("invalid json"); err != nil {
						t.Fatalf("Failed to write invalid json: %v", err)
					}
				}
				if _, err := f.Write([]byte(tt.content)); err != nil {
					t.Fatalf("Failed to write to temp file: %v", err)
				}
				defer f.Close()
				defer os.Remove(f.Name())
				tt.args.path = f.Name()
			}
			got, err := logRangesFromPath(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("logRangesFromPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("logRangesFromPath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpdateRange(t *testing.T) {
	type args struct {
		ctx context.Context
		r   LogRange
	}
	tests := []struct {
		name           string
		args           args
		want           LogRange
		wantErr        bool
		rootResponse   *trillian.GetLatestSignedLogRootResponse
		signedLogError error
	}{
		{
			name: "empty",
			args: args{
				ctx: context.Background(),
				r:   LogRange{},
			},
			want:    LogRange{},
			wantErr: true,
			rootResponse: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{},
			},
			signedLogError: nil,
		},
		{
			name: "error in GetLatestSignedLogRoot",
			args: args{
				ctx: context.Background(),
				r:   LogRange{},
			},
			want:    LogRange{},
			wantErr: true,
			rootResponse: &trillian.GetLatestSignedLogRootResponse{
				SignedLogRoot: &trillian.SignedLogRoot{},
			},
			signedLogError: errors.New("error"),
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, fakeServer, err := testonly.NewMockServer(mockCtl)
			if err != nil {
				t.Fatalf("Failed to create mock server: %v", err)
			}
			defer fakeServer()

			s.Log.EXPECT().GetLatestSignedLogRoot(
				gomock.Any(), gomock.Any()).Return(tt.rootResponse, tt.signedLogError).AnyTimes()
			got, err := updateRange(tt.args.ctx, s.LogClient, tt.args.r, false)

			if (err != nil) != tt.wantErr {
				t.Errorf("updateRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("updateRange() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLogRangesWithMock(t *testing.T) {
	keyPath, ecdsaSigner, pemPubKey, logID := initializeSigner(t)
	sc := signer.SigningConfig{SigningSchemeOrKeyPath: keyPath}

	type args struct {
		ctx    context.Context
		path   string
		treeID int64
	}
	tests := []struct {
		name    string
		args    args
		want    LogRanges
		wantErr bool
	}{
		{
			name: "empty path",
			args: args{
				ctx:    context.Background(),
				path:   "",
				treeID: 1,
			},
			want: LogRanges{
				active: LogRange{
					TreeID:        1,
					TreeLength:    0,
					SigningConfig: sc,
					Signer:        ecdsaSigner,
					PemPubKey:     pemPubKey,
					LogID:         logID,
				},
			},
			wantErr: false,
		},
		{
			name: "treeID 0",
			args: args{
				ctx:    context.Background(),
				path:   "x",
				treeID: 0,
			},
			want:    LogRanges{},
			wantErr: true,
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			s, fakeServer, err := testonly.NewMockServer(mockCtl)
			if err != nil {
				t.Fatalf("Failed to create mock server: %v", err)
			}
			defer fakeServer()
			got, err := NewLogRanges(tt.args.ctx, s.LogClient, tt.args.path, tt.args.treeID, sc)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLogRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				logRangesEqual(t, tt.want, got)
			}
		})
	}
}

// initializeSigner returns a path to an ECDSA private key, an ECDSA signer,
// PEM-encoded public key, and log ID
func initializeSigner(t *testing.T) (string, signature.Signer, string, string) {
	td := t.TempDir()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemPrivKey, err := cryptoutils.MarshalPrivateKeyToPEM(privKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signature.LoadECDSASigner(privKey, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	// Encode public key
	pubKey, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pemPubKey, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	// Calculate log ID
	b, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	pubkeyHashBytes := sha256.Sum256(b)
	logID := hex.EncodeToString(pubkeyHashBytes[:])

	keyFile := filepath.Join(td, fmt.Sprintf("%s-ecdsa-key.pem", logID))
	if err := os.WriteFile(keyFile, pemPrivKey, 0644); err != nil {
		t.Fatal(err)
	}

	return keyFile, signer, string(pemPubKey), logID
}

func logRangesEqual(t *testing.T, expected, got LogRanges) {
	logRangeEqual(t, expected.active, got.active)
	if len(expected.inactive) != len(got.inactive) {
		t.Fatalf("inactive log ranges are not equal")
	}
	for i, lr := range expected.inactive {
		g := got.inactive[i]
		logRangeEqual(t, lr, g)
	}
}

func logRangeEqual(t *testing.T, expected, got LogRange) {
	if expected.TreeID != got.TreeID {
		t.Fatalf("expected tree ID %v, got %v", expected.TreeID, got.TreeID)
	}
	if expected.TreeLength != got.TreeLength {
		t.Fatalf("expected tree length %v, got %v", expected.TreeLength, got.TreeLength)
	}
	if !reflect.DeepEqual(expected.SigningConfig, got.SigningConfig) {
		t.Fatalf("expected signing config %v, got %v", expected.SigningConfig, got.SigningConfig)
	}
	expectedPubKey, err := expected.Signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	gotPubKey, err := got.Signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := cryptoutils.EqualKeys(expectedPubKey, gotPubKey); err != nil {
		t.Fatal(err)
	}
	if expected.PemPubKey != got.PemPubKey {
		t.Fatalf("expected public key %v, got %v", expected.PemPubKey, got.PemPubKey)
	}
	if expected.LogID != got.LogID {
		t.Fatalf("expected log ID %v, got %v", expected.LogID, got.LogID)
	}
}
