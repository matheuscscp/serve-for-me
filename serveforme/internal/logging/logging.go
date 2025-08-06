package logging

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

type contextKey struct{}

func FromContext(ctx context.Context) logrus.FieldLogger {
	if logger, ok := ctx.Value(contextKey{}).(logrus.FieldLogger); ok {
		return logger
	}
	l := logrus.New()
	l.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	})
	if os.Getenv("DEBUG") != "" {
		l.SetLevel(logrus.DebugLevel)
	}
	return l
}

func IntoContext(ctx context.Context, logger logrus.FieldLogger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}
