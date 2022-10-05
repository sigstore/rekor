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

package client

import (
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestMakeOptions(t *testing.T) {
	customLogger := log.New(os.Stdout, "", log.LstdFlags)

	tests := []struct {
		desc string

		opts []Option
		want *options
	}{{
		desc: "no opts",
		want: &options{RetryCount: DefaultRetryCount},
	}, {
		desc: "WithUserAgent",
		opts: []Option{WithUserAgent("test user agent")},
		want: &options{UserAgent: "test user agent", RetryCount: DefaultRetryCount},
	}, {
		desc: "WithRetryCount",
		opts: []Option{WithRetryCount(2)},
		want: &options{UserAgent: "", RetryCount: 2},
	}, {
		desc: "WithLogger",
		opts: []Option{WithLogger(customLogger)},
		want: &options{UserAgent: "", RetryCount: DefaultRetryCount, Logger: customLogger},
	}, {
		desc: "WithLoggerNil",
		opts: []Option{WithLogger(nil)},
		want: &options{UserAgent: "", RetryCount: DefaultRetryCount},
	}}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := makeOptions(tc.opts...)
			if d := cmp.Diff(tc.want, got, cmp.Comparer(func(a, b *log.Logger) bool { return a == b })); d != "" {
				t.Errorf("makeOptions(%v) returned unexpected result (-want +got): %s", tc.desc, d)
			}
		})
	}
}

type mockRoundTripper struct {
	gotReqs []*http.Request

	resp *http.Response
	err  error
}

// RoundTrip implements `http.RoundTripper`
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.gotReqs = append(m.gotReqs, req)
	return m.resp, m.err
}

func TestCreateRoundTripper(t *testing.T) {
	t.Run("always returns non-nil", func(t *testing.T) {
		got := createRoundTripper(nil, &options{})
		if got == nil {
			t.Errorf("createRoundTripper() should never return a nil `http.RoundTripper`")
		}
	})

	testReq, err := http.NewRequest("GET", "http://www.example.com/test", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	testResp := &http.Response{
		Status:     "OK",
		StatusCode: 200,
		Request:    testReq,
	}

	expectedUserAgent := "test UserAgent"

	m := &mockRoundTripper{}
	rt := createRoundTripper(m, &options{
		UserAgent: expectedUserAgent,
	})
	m.resp = testResp

	gotResp, err := rt.RoundTrip(testReq)
	if err != nil {
		t.Errorf("RoundTrip() returned error: %v", err)
	}
	if len(m.gotReqs) < 1 {
		t.Fatalf("inner RoundTripper.RoundTrip() was not called")
	}
	gotReq := m.gotReqs[0]
	gotReqUserAgent := gotReq.UserAgent()
	if gotReqUserAgent != expectedUserAgent {
		t.Errorf("rt.RoundTrip() did not set the User-Agent properly. Wanted: %q, got: %q", expectedUserAgent, gotReqUserAgent)
	}

	if testResp != gotResp {
		t.Errorf("roundTripper.RoundTrip() should have returned exactly the response of the inner RoundTripper. Wanted %v, got %v", testResp, gotResp)
	}
}
