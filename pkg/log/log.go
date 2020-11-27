package log

import (
	"context"
	"log"

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
		log.Fatalln("createLogger", err)
	}

	return logger.Sugar()
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, middleware.RequestIDKey, id)
}

func RequestIDLogger(ctx context.Context) *zap.SugaredLogger {
	if ctxRequestID, ok := ctx.Value(middleware.RequestIDKey).(string); ok {
		return Logger.With(zap.String("requestID", ctxRequestID))
	}
	return Logger
}
