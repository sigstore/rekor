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
