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

func TestIsDebugEnabled(t *testing.T) {
	origLogger := Logger
	t.Cleanup(func() {
		Logger = origLogger
	})

	Logger = nil
	if IsDebugEnabled() {
		t.Fatalf("expected IsDebugEnabled() == false when Logger is nil")
	}

	infoCore, _ := observer.New(zap.InfoLevel)
	Logger = zap.New(infoCore).Sugar()
	if IsDebugEnabled() {
		t.Fatalf("expected IsDebugEnabled() == false at InfoLevel")
	}

	debugCore, _ := observer.New(zap.DebugLevel)
	Logger = zap.New(debugCore).Sugar()
	if !IsDebugEnabled() {
		t.Fatalf("expected IsDebugEnabled() == true at DebugLevel")
	}
}

func TestDebugHelpers(t *testing.T) {
	origLogger := Logger
	origPrefix := traceStringPrefix
	t.Cleanup(func() {
		Logger = origLogger
		traceStringPrefix = origPrefix
	})

	traceStringPrefix = ""
	ctx := WithRequestID(context.Background(), "req-debug")

	t.Run("disabled at InfoLevel", func(t *testing.T) {
		core, logs := observer.New(zap.InfoLevel)
		Logger = zap.New(core).Sugar()

		Debug(ctx, "ignored")
		Debugf(ctx, "ignored %d", 42)
		if logs.Len() != 0 {
			t.Fatalf("expected 0 log entries at InfoLevel, got %d", logs.Len())
		}
	})

	t.Run("enabled at DebugLevel", func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)
		Logger = zap.New(core).Sugar()

		Debug(ctx, "hello")
		Debugf(ctx, "count %d", 7)
		entries := logs.All()
		if len(entries) != 2 {
			t.Fatalf("expected 2 log entries at DebugLevel, got %d", len(entries))
		}
		if entries[0].Message != "hello" {
			t.Fatalf("unexpected first message: %q", entries[0].Message)
		}
		if entries[1].Message != "count 7" {
			t.Fatalf("unexpected second message: %q", entries[1].Message)
		}
		if _, exists := entries[0].ContextMap()["operation"]; !exists {
			t.Fatalf("expected operation field on Debug log")
		}
	})
}

func BenchmarkContextLogger(b *testing.B) {
	origLogger := Logger
	origPrefix := traceStringPrefix
	b.Cleanup(func() {
		Logger = origLogger
		traceStringPrefix = origPrefix
	})

	ConfigureLogger("prod", "projects/project-rekor/traces")
	ctx := WithRequestID(context.Background(), "122399bb012526bf9d97c30fb2afe723/12817094456274136198;o=1")

	b.Run("debugf_helper_disabled", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			Debugf(ctx, "log entry %d", 1)
		}
	})

	b.Run("unguarded_context_logger", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			ContextLogger(ctx).Debugf("log entry %d", 1)
		}
	})
}
