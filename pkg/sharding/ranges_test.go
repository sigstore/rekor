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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/trillian/testonly"

	"github.com/google/trillian"
	"google.golang.org/grpc"
	"gopkg.in/yaml.v2"
)

func TestNewLogRanges(t *testing.T) {
	contents := `
- treeID: 0001
  treeLength: 3
  encodedPublicKey: c2hhcmRpbmcK
- treeID: 0002
  treeLength: 4`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	treeID := uint(45)
	expected := LogRanges{
		inactive: []LogRange{
			{
				TreeID:           1,
				TreeLength:       3,
				EncodedPublicKey: "c2hhcmRpbmcK",
				decodedPublicKey: "sharding\n",
			}, {
				TreeID:     2,
				TreeLength: 4,
			},
		},
		active: int64(45),
	}
	ctx := context.Background()
	tc := trillian.NewTrillianLogClient(&grpc.ClientConn{})
	got, err := NewLogRanges(ctx, tc, file, treeID)
	if err != nil {
		t.Fatal(err)
	}
	if expected.ActiveTreeID() != got.ActiveTreeID() {
		t.Fatalf("expected tree id %d got %d", expected.ActiveTreeID(), got.ActiveTreeID())
	}
	if !reflect.DeepEqual(expected.GetInactive(), got.GetInactive()) {
		t.Fatalf("expected %v got %v", expected.GetInactive(), got.GetInactive())
	}
}

func TestLogRangesFromPath(t *testing.T) {
	contents := `
- treeID: 0001
  treeLength: 3
  encodedPublicKey: c2hhcmRpbmcK
- treeID: 0002
  treeLength: 4`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := Ranges{
		{
			TreeID:           1,
			TreeLength:       3,
			EncodedPublicKey: "c2hhcmRpbmcK",
		}, {
			TreeID:     2,
			TreeLength: 4,
		},
	}

	got, err := logRangesFromPath(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v got %v", expected, got)
	}
}

func TestLogRangesFromPathJSON(t *testing.T) {
	contents := `[{"treeID": 0001, "treeLength": 3, "encodedPublicKey":"c2hhcmRpbmcK"}, {"treeID": 0002, "treeLength": 4}]`
	file := filepath.Join(t.TempDir(), "sharding-config")
	if err := os.WriteFile(file, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	expected := Ranges{
		{
			TreeID:           1,
			TreeLength:       3,
			EncodedPublicKey: "c2hhcmRpbmcK",
		}, {
			TreeID:     2,
			TreeLength: 4,
		},
	}

	got, err := logRangesFromPath(file)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, got) {
		t.Fatalf("expected %v got %v", expected, got)
	}
}

func TestLogRanges_ResolveVirtualIndex(t *testing.T) {
	lrs := LogRanges{
		inactive: []LogRange{
			{TreeID: 1, TreeLength: 17},
			{TreeID: 2, TreeLength: 1},
			{TreeID: 3, TreeLength: 100},
		},
		active: 4,
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

func TestPublicKey(t *testing.T) {
	ranges := LogRanges{
		active: 45,
		inactive: []LogRange{
			{
				TreeID:           10,
				TreeLength:       10,
				decodedPublicKey: "sharding",
			}, {
				TreeID:     20,
				TreeLength: 20,
			},
		},
	}
	activePubKey := "activekey"
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
			expectedPubKey: "sharding",
		}, {
			description:    "tree id without decoded public key",
			treeID:         "20",
			expectedPubKey: "activekey",
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
			got, err := ranges.PublicKey(activePubKey, test.treeID)
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
		active   int64
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
				active:   0,
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
				active: 3,
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
				active: 4,
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
		active   int64
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
				active:   0,
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
				active: 3,
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
		active   int64
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
				active:   0,
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
				active: 3,
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
				active: 4,
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

func Test_logRangesFromPath(t *testing.T) {
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
				defer os.Remove(f.Name())
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

func Test_updateRange(t *testing.T) {
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
			got, err := updateRange(tt.args.ctx, s.LogClient, tt.args.r)

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

func TestNewLogRanges1(t *testing.T) {
	type args struct {
		ctx    context.Context
		path   string
		treeID uint
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
			want:    LogRanges{},
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
			got, err := NewLogRanges(tt.args.ctx, s.LogClient, tt.args.path, tt.args.treeID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLogRanges() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLogRanges() got = %v, want %v", got, tt.want)
			}
		})
	}
}
