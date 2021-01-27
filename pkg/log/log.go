package log

import (
	"context"
	"log"
	"net/http"

	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Set the default logger to development mode
var Logger *zap.SugaredLogger

func init() {
	ConfigureLogger("dev")
}

func ConfigureLogger(logType string) {
	var cfg zap.Config
	if logType == "prod" {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
	}
	Logger = logger.Sugar()
}

var CliLogger = createCliLogger()

func createCliLogger() *zap.SugaredLogger {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.TimeKey = ""
	cfg.EncoderConfig.LevelKey = ""
	cfg.DisableCaller = true
	logger, err := cfg.Build()
	if err != nil {
		log.Fatalln("createLogger", err)
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
