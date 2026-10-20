// Copyright 2026 The Sigstore Authors.
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

package jcs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestRFC8785Vectors checks the test vectors from the reference implementation
// (see testdata/README.md).
func TestRFC8785Vectors(t *testing.T) {
	inputs, err := filepath.Glob("testdata/input/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("no test vectors found")
	}
	for _, in := range inputs {
		t.Run(filepath.Base(in), func(t *testing.T) {
			b, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata/output", filepath.Base(in)))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonicalize(b)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, bytes.TrimRight(want, "\n")) {
				t.Errorf("got  %q\nwant %q", got, want)
			}
		})
	}
}

// TestCompatibility pins rekor-shaped payloads to the output of
// github.com/cyberphone/json-canonicalization, which rekor used previously.
// Any change here alters entry UUIDs and signed bytes.
func TestCompatibility(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "hashedrekord body as marshaled by go-swagger (kind last)",
			in:   "{\"apiVersion\":\"0.0.1\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"d7c4a1a2a7f2d1c6e8a0f5b3c9e2d4a6b8c0e2f4a6b8c0d2e4f6a8b0c2d4e6f8\"}},\"signature\":{\"content\":\"MEUCIQDx3f4+bN1Lr4tq3Kp0p0e2Y5xJ8cK3sYq0VtA1hL2mWQIgO8zR3n0Wc5q3m0R1yH9d6m7oX5s2kQ3Vn0rP2tL4xYs=\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=\"}}},\"kind\":\"hashedrekord\"}",
			want: "{\"apiVersion\":\"0.0.1\",\"kind\":\"hashedrekord\",\"spec\":{\"data\":{\"hash\":{\"algorithm\":\"sha256\",\"value\":\"d7c4a1a2a7f2d1c6e8a0f5b3c9e2d4a6b8c0e2f4a6b8c0d2e4f6a8b0c2d4e6f8\"}},\"signature\":{\"content\":\"MEUCIQDx3f4+bN1Lr4tq3Kp0p0e2Y5xJ8cK3sYq0VtA1hL2mWQIgO8zR3n0Wc5q3m0R1yH9d6m7oX5s2kQ3Vn0rP2tL4xYs=\",\"publicKey\":{\"content\":\"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=\"}}}}",
		},
		{
			name: "log entry signing payload",
			in:   "{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==\",\"integratedTime\":1760000000,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\",\"logIndex\":123456789}",
			want: "{\"body\":\"eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==\",\"integratedTime\":1760000000,\"logID\":\"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d\",\"logIndex\":123456789}",
		},
		{
			name: "free-form string map with non-ASCII, control and PUA characters",
			in:   "{\"apiVersion\":\"0.0.1\",\"spec\":{\"package\":{\"headers\":{\"Name\":\"a&b<c>d\",\"Summary\":\"\u2028 emoji 😀 é \\u0000\\u001f\\u007f\",\"\ue000\":\"pua\",\"Version\":\"1.0\"}},\"publicKey\":null},\"kind\":\"rpm\"}",
			want: "{\"apiVersion\":\"0.0.1\",\"kind\":\"rpm\",\"spec\":{\"package\":{\"headers\":{\"Name\":\"a&b<c>d\",\"Summary\":\"\u2028 emoji 😀 é \\u0000\\u001f\x7f\",\"Version\":\"1.0\",\"\ue000\":\"pua\"}},\"publicKey\":null}}",
		},
		{
			name: "HTML escapes emitted by encoding/json",
			in:   `{"a":"\u0026\u003c\u003e"}`,
			want: `{"a":"&<>"}`,
		},
		{
			name: "numbers",
			in:   "{\"z\":[12345678901234567890123,9007199254740993,1E21,1e-7,0.000001,-0,1e-400,1.5e300,100,1.0]}",
			want: "{\"z\":[1.2345678901234568e+22,9007199254740992,1e+21,1e-7,0.000001,0,0,1.5e+300,100,1]}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestNumberRange(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: `{"n":1e400}`, wantErr: true},
		{in: `{"n":-1e400}`, wantErr: true},
		{in: `{"a":{"b":[1,2,1e309]}}`, wantErr: true},
		{in: `{"n":1.7976931348623157e308,"m":1e400}`, wantErr: true},
		// The largest finite values are fine; only overflow is rejected.
		{in: `{"n":1.7976931348623157e308}`, want: `{"n":1.7976931348623157e+308}`},
		{in: `{"n":-1.7976931348623157e308}`, want: `{"n":-1.7976931348623157e+308}`},
		// The token inside a string must not trip the check.
		{in: `{"s":"1.7976931348623157e+308","t":"1e400"}`, want: `{"s":"1.7976931348623157e+308","t":"1e400"}`},
		// Underflow rounds to zero, as the previous implementation did.
		{in: `{"n":1e-400}`, want: `{"n":0}`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalid(t *testing.T) {
	for _, in := range []string{
		``,
		`{"a":1,"a":2}`,
		"{\"a\":\"\xff\"}",
		`{"a":"\ud800"}`,
		`{"a":1} trailing`,
		`{"a":01}`,
		`{"a":NaN}`,
		strings.Repeat("[", 10001) + strings.Repeat("]", 10001),
	} {
		if got, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%.40q) = %q, expected error", in, got)
		}
	}
}

func TestDoesNotModifyInput(t *testing.T) {
	in := []byte(`{ "b": 1, "a": [ 1.0, "A" ] }`)
	orig := bytes.Clone(in)
	if _, err := Canonicalize(in); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, orig) {
		t.Errorf("input modified: %q", in)
	}
}

func FuzzCanonicalize(f *testing.F) {
	inputs, _ := filepath.Glob("testdata/input/*.json")
	for _, in := range inputs {
		if b, err := os.ReadFile(in); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{"n":1e400}`))
	f.Add([]byte(`{"s":"1.7976931348623157e+308"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := Canonicalize(b)
		if err != nil {
			return
		}
		again, err := Canonicalize(out)
		if err != nil {
			t.Fatalf("canonical output rejected: %v", err)
		}
		if !bytes.Equal(out, again) {
			t.Fatalf("not idempotent:\n%q\n%q", out, again)
		}
		var v1, v2 any
		if err := json.Unmarshal(b, &v1); err != nil {
			t.Fatalf("accepted input that encoding/json rejects: %v", err)
		}
		if err := json.Unmarshal(out, &v2); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if !reflect.DeepEqual(v1, v2) {
			t.Fatalf("value changed:\n%#v\n%#v", v1, v2)
		}
	})
}

func BenchmarkCanonicalize(b *testing.B) {
	in := []byte(`{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEifQ==","integratedTime":1760000000,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":123456789}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Canonicalize(in); err != nil {
			b.Fatal(err)
		}
	}
}
