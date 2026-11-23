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

package log

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	internallog "github.com/sigstore/rekor/pkg/internal/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger set the default logger to development mode
var Logger *zap.SugaredLogger

var traceStringPrefix string

func init() {
	ConfigureLogger("dev", "")
}

func ConfigureLogger(logType, traceStrPrefix string) {
	var cfg zap.Config
	if logType == "prod" {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.LevelKey = "severity"
		cfg.EncoderConfig.MessageKey = "message"
		cfg.EncoderConfig.TimeKey = "time"
		cfg.EncoderConfig.EncodeLevel = encodeLevel()
		cfg.EncoderConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
		cfg.EncoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
		cfg.EncoderConfig.EncodeCaller = zapcore.FullCallerEncoder
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
	}
	Logger = logger.Sugar()
	internallog.Logger = Logger

	if traceStrPrefix != "" {
		traceStringPrefix = strings.TrimRight(traceStrPrefix, "/")
	}
}

func encodeLevel() zapcore.LevelEncoder {
	return func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		switch l {
		case zapcore.DebugLevel:
			enc.AppendString("DEBUG")
		case zapcore.InfoLevel:
			enc.AppendString("INFO")
		case zapcore.WarnLevel:
			enc.AppendString("WARNING")
		case zapcore.ErrorLevel:
			enc.AppendString("ERROR")
		case zapcore.DPanicLevel:
			enc.AppendString("CRITICAL")
		case zapcore.PanicLevel:
			enc.AppendString("ALERT")
		case zapcore.FatalLevel:
			enc.AppendString("EMERGENCY")
		}
	}
}

var CliLogger = createCliLogger()

func createCliLogger() *zap.SugaredLogger {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.TimeKey = ""
	cfg.EncoderConfig.LevelKey = ""
	cfg.DisableCaller = true
	cfg.DisableStacktrace = true
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
	}

	return logger.Sugar()
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, middleware.RequestIDKey, id)
}

type operation struct {
	id string
}

func (o operation) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("id", o.id)
	return nil
}

func isHexString(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// parseTraceContext extracts a trace ID and 16-char lowercase hex span ID from
// either X-Cloud-Trace-Context ("<trace_id>/<decimal_span_id>[;o=<opts>]") or
// W3C traceparent ("00-<32-hex-trace_id>-<16-hex-span_id>-<flags>").
func parseTraceContext(raw string) (traceID, spanID string) {
	// Fast path for W3C traceparent: "<ver>-<32-hex>-<16-hex>-<flags>"
	if _, rest, ok := strings.Cut(raw, "-"); ok {
		if t, rest2, ok := strings.Cut(rest, "-"); ok && len(t) == 32 {
			if s, rest3, ok := strings.Cut(rest2, "-"); ok && len(s) == 16 && !strings.Contains(rest3, "-") {
				if isHexString(t) && isHexString(s) {
					return strings.ToLower(t), strings.ToLower(s)
				}
			}
		}
	}

	traceAndSpan, _, _ := strings.Cut(raw, ";")
	t, s, hasSpan := strings.Cut(traceAndSpan, "/")
	if len(t) != 32 || !isHexString(t) {
		return "", ""
	}
	traceID = strings.ToLower(t)
	if hasSpan && s != "" {
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			spanID = fmt.Sprintf("%016x", u)
		} else if len(s) == 16 && isHexString(s) {
			spanID = strings.ToLower(s)
		}
	}
	return traceID, spanID
}

// IsDebugEnabled reports whether debug-level logging is enabled on Logger.
func IsDebugEnabled() bool {
	return Logger != nil && Logger.Level().Enabled(zapcore.DebugLevel)
}

// Debug logs args at debug level with request context attached, avoiding
// ContextLogger allocation when debug logging is disabled.
func Debug(ctx context.Context, args ...any) {
	if !IsDebugEnabled() {
		return
	}
	ContextLogger(ctx).WithOptions(zap.AddCallerSkip(1)).Debug(args...)
}

// Debugf formats and logs a message at debug level with request context
// attached, avoiding ContextLogger allocation when debug logging is disabled.
func Debugf(ctx context.Context, template string, args ...any) {
	if !IsDebugEnabled() {
		return
	}
	ContextLogger(ctx).WithOptions(zap.AddCallerSkip(1)).Debugf(template, args...)
}

func ContextLogger(ctx context.Context) *zap.SugaredLogger {
	proposedLogger := Logger
	if ctx != nil {
		if ctxRequestID, ok := ctx.Value(middleware.RequestIDKey).(string); ok && ctxRequestID != "" {
			if traceStringPrefix != "" {
				traceID, spanID := parseTraceContext(ctxRequestID)
				switch {
				case traceID != "" && spanID != "":
					proposedLogger = proposedLogger.With(
						zap.String("logging.googleapis.com/trace", traceStringPrefix+"/"+traceID),
						zap.String("logging.googleapis.com/spanId", spanID),
					)
				case traceID != "":
					proposedLogger = proposedLogger.With(
						zap.String("logging.googleapis.com/trace", traceStringPrefix+"/"+traceID),
					)
				case spanID != "":
					proposedLogger = proposedLogger.With(
						zap.String("logging.googleapis.com/spanId", spanID),
					)
				}
			} else {
				requestID := operation{ctxRequestID}
				proposedLogger = proposedLogger.With(zap.Object("operation", requestID))
			}
		}
	}
	return proposedLogger
}
