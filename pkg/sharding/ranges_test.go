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
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian"
	"github.com/google/trillian/testonly"
	"github.com/google/trillian/types"
	"github.com/sigstore/rekor/pkg/signer"
	"github.com/sigstore/rekor/pkg/trillianclient"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	got, err := NewLogRanges(ctx, file, treeID, sc)
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
	_, err = NewLogRanges(ctx, file, 0, sc)
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

func TestInitializeRange(t *testing.T) {
	keyPath, _, pemPubKey, logID := initializeSigner(t)
	sc := signer.SigningConfig{
		SigningSchemeOrKeyPath: keyPath,
	}

	tests := []struct {
		name      string
		rangeIn   LogRange
		wantRange LogRange
		wantErr   bool
	}{
		{
			name: "valid range",
			rangeIn: LogRange{
				TreeID:        1,
				SigningConfig: sc,
			},
			wantRange: LogRange{
				TreeID:        1,
				SigningConfig: sc,
				PemPubKey:     pemPubKey,
				LogID:         logID,
			},
			wantErr: false,
		},
		{
			name: "missing signing config",
			rangeIn: LogRange{
				TreeID: 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := initializeRange(ctx, tt.rangeIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("initializeRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Clear the signer for comparison, as it's not comparable
			if got.Signer != nil {
				got.Signer = nil
			}
			if !tt.wantErr {
				// Manually remove signer for comparison
				tt.wantRange.Signer = nil
				if !reflect.DeepEqual(got, tt.wantRange) {
					t.Errorf("initializeRange() = %v, want %v", got, tt.wantRange)
				}
			}
		})
	}
}

func setupMockServer(t *testing.T, mockCtl *gomock.Controller) (*testonly.MockServer, func()) {
	t.Helper()
	s, closeFn, err := testonly.NewMockServer(mockCtl)
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	return s, closeFn
}

func TestCompleteInitialization_Scenarios(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	// Shared setup for all scenarios
	keyPath, _, _, _ := initializeSigner(t)
	activeSC := signer.SigningConfig{
		SigningSchemeOrKeyPath: keyPath,
	}

	// --- Scenario 4: Connection Failure ---
	// Find an unused port for the connection failure test
	lisClosed, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	closedAddr := lisClosed.Addr().(*net.TCPAddr)
	lisClosed.Close() // Immediately close it

	// --- Test Case Definitions ---
	testCases := []struct {
		name          string
		setup         func(t *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager)
		expectErr     bool
		postCondition func(t *testing.T, logRanges *LogRanges, roots map[int64]types.LogRootV1)
	}{
		{
			name: "Scenario 1: Multiple Backends",
			setup: func(t *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager) {
				// Setup two inactive shards, each pointing to a different server
				inactive1, _ := initializeRange(context.Background(), LogRange{TreeID: 101, SigningConfig: activeSC})
				inactive2, _ := initializeRange(context.Background(), LogRange{TreeID: 102, SigningConfig: activeSC})
				logRanges.inactive = Ranges{inactive1, inactive2}

				// Create isolated servers for this scenario
				sA, closeA := setupMockServer(t, mockCtl)
				t.Cleanup(closeA)
				addrA := sA.Addr
				portA, err := strconv.Atoi(addrA[strings.LastIndex(addrA, ":")+1:])
				require.NoError(t, err)

				sB, closeB := setupMockServer(t, mockCtl)
				t.Cleanup(closeB)
				addrB := sB.Addr
				portB, err := strconv.Atoi(addrB[strings.LastIndex(addrB, ":")+1:])
				require.NoError(t, err)

				// Mock responses from each server
				root1 := &types.LogRootV1{TreeSize: 42}
				rootBytes1, _ := root1.MarshalBinary()
				sA.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: rootBytes1}}, nil).MinTimes(1)

				root2 := &types.LogRootV1{TreeSize: 84}
				rootBytes2, _ := root2.MarshalBinary()
				sB.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: rootBytes2}}, nil).MinTimes(1)

				// Configure client manager to route to the correct servers
				grpcConfigs := map[int64]trillianclient.GRPCConfig{
					101: {Address: "localhost", Port: uint16(portA)},
					102: {Address: "localhost", Port: uint16(portB)},
				}
				*tcm = trillianclient.NewClientManager(grpcConfigs, trillianclient.GRPCConfig{}, trillianclient.DefaultConfig())
			},
			expectErr: false,
			postCondition: func(t *testing.T, logRanges *LogRanges, roots map[int64]types.LogRootV1) {
				require.Len(t, logRanges.inactive, 2)
				t.Log(logRanges.inactive)
				require.Equal(t, int64(42), logRanges.inactive[0].TreeLength)
				require.Equal(t, int64(84), logRanges.inactive[1].TreeLength)
				require.Len(t, roots, 2)
				require.Equal(t, uint64(42), roots[101].TreeSize)
				require.Equal(t, uint64(84), roots[102].TreeSize)
			},
		},
		{
			name: "Scenario 2: Fallback to Default Backend",
			setup: func(t *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager) {
				inactive, _ := initializeRange(context.Background(), LogRange{TreeID: 201, SigningConfig: activeSC})
				logRanges.inactive = Ranges{inactive}

				// Create a dedicated default backend for this scenario
				sDef, closeDef := setupMockServer(t, mockCtl)
				t.Cleanup(closeDef)
				addr := sDef.Addr
				port, err := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
				require.NoError(t, err)

				root := &types.LogRootV1{TreeSize: 99}
				rootBytes, _ := root.MarshalBinary()
				sDef.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(&trillian.GetLatestSignedLogRootResponse{SignedLogRoot: &trillian.SignedLogRoot{LogRoot: rootBytes}}, nil).MinTimes(1)

				// No specific config for tree 201, so it should use the default
				defaultConfig := trillianclient.GRPCConfig{Address: "localhost", Port: uint16(port)}
				*tcm = trillianclient.NewClientManager(map[int64]trillianclient.GRPCConfig{}, defaultConfig, trillianclient.DefaultConfig())
			},
			expectErr: false,
			postCondition: func(t *testing.T, logRanges *LogRanges, roots map[int64]types.LogRootV1) {
				require.Len(t, logRanges.inactive, 1)
				require.Equal(t, int64(99), logRanges.inactive[0].TreeLength)
				require.Len(t, roots, 1)
				require.Equal(t, uint64(99), roots[201].TreeSize)
			},
		},
		{
			name: "Scenario 3: No Inactive Shards",
			setup: func(_ *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager) {
				logRanges.inactive = Ranges{}
				// No inactive shards means the client manager won't be used.
				// Provide a no-op default config to satisfy constructor.
				*tcm = trillianclient.NewClientManager(nil, trillianclient.GRPCConfig{Address: "localhost", Port: 0}, trillianclient.DefaultConfig())
			},
			expectErr: false,
			postCondition: func(t *testing.T, logRanges *LogRanges, roots map[int64]types.LogRootV1) {
				require.Empty(t, logRanges.inactive)
				require.Empty(t, roots)
			},
		},
		{
			name: "Scenario 4: gRPC Connection Failure",
			setup: func(_ *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager) {
				inactive, _ := initializeRange(context.Background(), LogRange{TreeID: 401, SigningConfig: activeSC})
				logRanges.inactive = Ranges{inactive}

				// Point to a closed port
				grpcConfigs := map[int64]trillianclient.GRPCConfig{
					401: {Address: "localhost", Port: uint16(closedAddr.Port)},
				}
				*tcm = trillianclient.NewClientManager(grpcConfigs, trillianclient.GRPCConfig{}, trillianclient.DefaultConfig())
			},
			expectErr: true,
		},
		{
			name: "Scenario 5: Trillian API Error",
			setup: func(t *testing.T, logRanges *LogRanges, tcm **trillianclient.ClientManager) {
				inactive, _ := initializeRange(context.Background(), LogRange{TreeID: 501, SigningConfig: activeSC})
				logRanges.inactive = Ranges{inactive}

				// Create a dedicated backend that returns an error
				sErr, closeErr := setupMockServer(t, mockCtl)
				t.Cleanup(closeErr)
				addr := sErr.Addr
				port, err := strconv.Atoi(addr[strings.LastIndex(addr, ":")+1:])
				require.NoError(t, err)

				// Mock an error from the Trillian server
				sErr.Log.EXPECT().GetLatestSignedLogRoot(gomock.Any(), gomock.Any()).Return(nil, status.Error(codes.NotFound, "tree not found")).MinTimes(1)

				grpcConfigs := map[int64]trillianclient.GRPCConfig{
					501: {Address: "localhost", Port: uint16(port)},
				}
				*tcm = trillianclient.NewClientManager(grpcConfigs, trillianclient.GRPCConfig{}, trillianclient.DefaultConfig())
			},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a base LogRanges object for each test run
			logRanges, err := NewLogRanges(context.Background(), "", 1, activeSC)
			require.NoError(t, err)
			var tcm *trillianclient.ClientManager

			// Run the specific setup for the scenario
			tc.setup(t, logRanges, &tcm)

			// Execute the function under test
			roots, err := logRanges.CompleteInitialization(context.Background(), tcm)

			// Assert error expectation
			if tc.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// Run post-conditions if any
			if tc.postCondition != nil {
				tc.postCondition(t, logRanges, roots)
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

			got, err := NewLogRanges(tt.args.ctx, tt.args.path, tt.args.treeID, sc)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLogRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				logRangesEqual(t, tt.want, *got)
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
