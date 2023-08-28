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

package gcp

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/sigstore/rekor/pkg/events"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestParseRef(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		desc string
		ref  string

		wantProject string
		wantTopic   string
		wantErr     bool
	}{

		{
			desc:        "Valid example",
			ref:         "gcppubsub://projects/project-foo/topics/topic-bar",
			wantProject: "project-foo",
			wantTopic:   "topic-bar",
		},
		{
			desc:    "Empty ref",
			wantErr: true,
		},
		{
			desc:    "Missing topic",
			ref:     "gcppubsub://projects/project-foo/topics/",
			wantErr: true,
		},
		{
			desc:    "Wrong scheme",
			ref:     "foo://projects/project-foo/topics/topic-bar",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			project, topic, err := parseRef(tc.ref)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Errorf("parseRef(%s) error = %v, wantErr %v", tc.ref, gotErr, tc.wantErr)
				return
			}
			if project != tc.wantProject {
				t.Errorf("parseRef(%s) project = %s, want %s", tc.ref, project, tc.wantProject)
			}
			if topic != tc.wantTopic {
				t.Errorf("parseRef(%s) topic = %s, want %s", tc.ref, topic, tc.wantTopic)
			}
		})
	}
}

func TestGCPAttrs(t *testing.T) {
	t.Parallel()

	empty := &emptypb.Empty{}
	ty := events.RegisterType("gcpAttrsTestEvent", "/source", empty.ProtoReflect().Descriptor())

	coreEvent, err := ty.New("A123-456", &emptypb.Empty{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attrs := map[string]any{
		"attr_string":    "string",
		"attr_bool":      true,
		"attr_int":       123,
		"attr_bytes":     []byte("hello"),
		"attr_timestamp": time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Second),
	}
	attrsEvent, err := ty.New("A456-789", &emptypb.Empty{}, attrs)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		desc  string
		event *events.Event
		want  map[string]string
	}{
		{
			desc:  "Core attrs only",
			event: coreEvent,
			want: map[string]string{
				"datacontenttype": "application/fake-test-mime",
				"source":          "/source",
				"type":            "gcpAttrsTestEvent",
			},
		},
		{
			desc:  "With optional attrs",
			event: attrsEvent,
			want: map[string]string{
				"datacontenttype": "application/fake-test-mime",
				"source":          "/source",
				"type":            "gcpAttrsTestEvent",
				"attr_string":     "string",
				"attr_int":        "123",
				"attr_bool":       "true",
				"attr_bytes":      "aGVsbG8=",
				"attr_timestamp":  time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Second).Format(time.RFC3339),
			},
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			got := gcpAttrs(tc.event, "application/fake-test-mime")
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("unexpected diff:\n%s", diff)
			}
		})
	}
}
