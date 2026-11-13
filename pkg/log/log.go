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
	"encoding/hex"
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

// parseTraceContext extracts a trace ID and 16-char lowercase hex span ID from
// either X-Cloud-Trace-Context ("<trace_id>/<decimal_span_id>[;o=<opts>]") or
// W3C traceparent ("00-<32-hex-trace_id>-<16-hex-span_id>-<flags>").
func parseTraceContext(raw string) (traceID, spanID string) {
	if parts := strings.Split(raw, "-"); len(parts) == 4 && len(parts[1]) == 32 && len(parts[2]) == 16 {
		if _, err := hex.DecodeString(parts[1]); err == nil {
			if _, err := hex.DecodeString(parts[2]); err == nil {
				return strings.ToLower(parts[1]), strings.ToLower(parts[2])
			}
		}
	}

	traceAndSpan, _, _ := strings.Cut(raw, ";")
	t, s, hasSpan := strings.Cut(traceAndSpan, "/")
	if len(t) != 32 {
		return "", ""
	}
	if _, err := hex.DecodeString(t); err != nil {
		return "", ""
	}
	traceID = strings.ToLower(t)
	if hasSpan && s != "" {
		if u, err := strconv.ParseUint(s, 10, 64); err == nil {
			spanID = fmt.Sprintf("%016x", u)
		} else if len(s) == 16 {
			if _, err := hex.DecodeString(s); err == nil {
				spanID = strings.ToLower(s)
			}
		}
	}
	return traceID, spanID
}

func ContextLogger(ctx context.Context) *zap.SugaredLogger {
	proposedLogger := Logger
	if ctx != nil {
		if ctxRequestID, ok := ctx.Value(middleware.RequestIDKey).(string); ok && ctxRequestID != "" {
			if traceStringPrefix != "" {
				traceID, spanID := parseTraceContext(ctxRequestID)
				if traceID != "" {
					proposedLogger = proposedLogger.With(zap.String("logging.googleapis.com/trace", fmt.Sprintf("%s/%s", traceStringPrefix, traceID)))
				}
				if spanID != "" {
					proposedLogger = proposedLogger.With(zap.String("logging.googleapis.com/spanId", spanID))
				}
			} else {
				requestID := operation{ctxRequestID}
				proposedLogger = proposedLogger.With(zap.Object("operation", requestID))
			}
		}
	}
	return proposedLogger
}
