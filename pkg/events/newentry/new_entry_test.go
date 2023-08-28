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

package newentry

import (
	"math"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/rekor/pkg/events"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	events_pb "github.com/sigstore/protobuf-specs/gen/pb-go/events/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

func TestBuildNewEntryEvent(t *testing.T) {
	t.Parallel()

	decamillennium := time.Date(9999, 12, 31, 24, 59, 59, math.MaxInt, time.UTC).Unix()
	testEntry := &rekor_pb.TransparencyLogEntry{
		IntegratedTime: decamillennium,
		KindVersion: &rekor_pb.KindVersion{
			Kind: "test_kind",
		},
	}
	marshalledEntry, err := proto.Marshal(testEntry)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		desc     string
		entryID  string
		subjects []string
		entry    *rekor_pb.TransparencyLogEntry

		wantError bool
		want      *events_pb.CloudEvent
	}{
		{
			desc:      "missing ID",
			subjects:  []string{"test@rekor.dev"},
			entry:     testEntry,
			wantError: true,
		},
		{
			desc:     "valid",
			entryID:  "test-id",
			subjects: []string{"test@rekor.dev", "foo@bar.baz"}, // Output should be sorted.
			entry:    testEntry,
			want: &events_pb.CloudEvent{
				SpecVersion: events.CloudEventsSpecVersion,
				Id:          "test-id",
				Source:      Source,
				Type:        Name,
				Attributes: map[string]*events_pb.CloudEvent_CloudEventAttributeValue{
					"time": {Attr: &events_pb.CloudEvent_CloudEventAttributeValue_CeTimestamp{
						CeTimestamp: &timestamppb.Timestamp{Seconds: decamillennium},
					}},
					"rekor_entry_kind": {Attr: &events_pb.CloudEvent_CloudEventAttributeValue_CeString{
						CeString: "test_kind",
					}},
					"rekor_signing_subjects": {Attr: &events_pb.CloudEvent_CloudEventAttributeValue_CeString{
						CeString: "foo@bar.baz,test@rekor.dev",
					}},
				},
				Data: &events_pb.CloudEvent_ProtoData{
					ProtoData: &anypb.Any{
						Value:   marshalledEntry,
						TypeUrl: string(testEntry.ProtoReflect().Descriptor().FullName()),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			event, err := New(tc.entryID, tc.entry, tc.subjects)
			gotErr := err != nil
			if gotErr != tc.wantError {
				t.Fatalf("New() err = %v, want %v", gotErr, tc.wantError)
			}
			if err != nil {
				return
			}
			msg, err := event.Proto()
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(msg, tc.want, protocmp.Transform()); diff != "" {
				t.Errorf("New() unexpected diff:\n%s", diff)
			}
		})
	}
}
