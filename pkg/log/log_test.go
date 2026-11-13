//
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

package log

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestParseTraceContext(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantTrace string
		wantSpan  string
	}{
		{
			name:      "cloud trace context with decimal span",
			input:     "122399bb012526bf9d97c30fb2afe723/12817094456274136198",
			wantTrace: "122399bb012526bf9d97c30fb2afe723",
			wantSpan:  "b1df778006d92c86",
		},
		{
			name:      "cloud trace context with options",
			input:     "122399bb012526bf9d97c30fb2afe723/12817094456274136198;o=1",
			wantTrace: "122399bb012526bf9d97c30fb2afe723",
			wantSpan:  "b1df778006d92c86",
		},
		{
			name:      "cloud trace context with small span zero-padded",
			input:     "122399bb012526bf9d97c30fb2afe723/42;o=0",
			wantTrace: "122399bb012526bf9d97c30fb2afe723",
			wantSpan:  "000000000000002a",
		},
		{
			name:      "cloud trace context without span",
			input:     "122399bb012526bf9d97c30fb2afe723;o=1",
			wantTrace: "122399bb012526bf9d97c30fb2afe723",
			wantSpan:  "",
		},
		{
			name:      "w3c traceparent",
			input:     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
			wantTrace: "4bf92f3577b34da6a3ce929d0e0e4736",
			wantSpan:  "00f067aa0ba902b7",
		},
		{
			name:      "plain request id rejected as trace",
			input:     "rekor-server-000001",
			wantTrace: "",
			wantSpan:  "",
		},
		{
			name:      "malformed non-hex trace id rejected",
			input:     "../other-project/traces/evil/1234",
			wantTrace: "",
			wantSpan:  "",
		},
		{
			name:      "oversized trace id rejected",
			input:     "122399bb012526bf9d97c30fb2afe723deadbeef/1234",
			wantTrace: "",
			wantSpan:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTrace, gotSpan := parseTraceContext(tc.input)
			if gotTrace != tc.wantTrace || gotSpan != tc.wantSpan {
				t.Fatalf("parseTraceContext(%q) = (%q, %q), want (%q, %q)", tc.input, gotTrace, gotSpan, tc.wantTrace, tc.wantSpan)
			}
		})
	}
}

func TestContextLogger(t *testing.T) {
	origLogger := Logger
	origPrefix := traceStringPrefix
	t.Cleanup(func() {
		Logger = origLogger
		traceStringPrefix = origPrefix
	})

	t.Run("with trace prefix and X-Cloud-Trace-Context", func(t *testing.T) {
		ConfigureLogger("dev", "projects/project-rekor/traces/")
		core, logs := observer.New(zap.InfoLevel)
		Logger = zap.New(core).Sugar()

		ctx := WithRequestID(context.Background(), "122399bb012526bf9d97c30fb2afe723/12817094456274136198;o=1")
		ContextLogger(ctx).Info("hello")

		entries := logs.All()
		if len(entries) != 1 {
			t.Fatalf("expected 1 log entry, got %d", len(entries))
		}
		fields := entries[0].ContextMap()
		if got := fields["logging.googleapis.com/trace"]; got != "projects/project-rekor/traces/122399bb012526bf9d97c30fb2afe723" {
			t.Fatalf("unexpected trace field: %v", got)
		}
		if got := fields["logging.googleapis.com/spanId"]; got != "b1df778006d92c86" {
			t.Fatalf("unexpected spanId field: %v", got)
		}
		if _, exists := fields["operation"]; exists {
			t.Fatalf("expected no operation field when traceStringPrefix is set, got %v", fields["operation"])
		}
	})

	t.Run("without trace prefix preserves operation field", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		Logger = zap.New(core).Sugar()
		traceStringPrefix = ""

		ctx := WithRequestID(context.Background(), "req-123")
		ContextLogger(ctx).Info("hello")

		entries := logs.All()
		if len(entries) != 1 {
			t.Fatalf("expected 1 log entry, got %d", len(entries))
		}
		fields := entries[0].ContextMap()
		if _, exists := fields["logging.googleapis.com/trace"]; exists {
			t.Fatalf("expected no trace field when traceStringPrefix is empty")
		}
		if _, exists := fields["operation"]; !exists {
			t.Fatalf("expected operation field when traceStringPrefix is empty")
		}
	})
}
