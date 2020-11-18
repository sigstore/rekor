package log

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger = createGlobalLogger()

func createGlobalLogger() *zap.SugaredLogger {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err.Error)
	}

	return logger.Sugar()
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, middleware.RequestIDKey, id)
}

func RequestIDLogger(r *http.Request) *zap.SugaredLogger {
	proposedLogger := Logger
	if r != nil {
		if ctxRequestID, ok := r.Context().Value(middleware.RequestIDKey).(string); ok {
			proposedLogger = proposedLogger.With(zap.String("requestID", ctxRequestID))
		}
	}
	return proposedLogger
}
