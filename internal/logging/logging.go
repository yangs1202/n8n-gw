package logging

import (
	"log/slog"
	"os"
	"strings"
)

var sensitiveKeys = map[string]struct{}{
	"password":      {},
	"n8n_password":  {},
	"authorization": {},
	"cookie":        {},
	"set-cookie":    {},
	"id_token":      {},
	"access_token":  {},
	"refresh_token": {},
	"code":          {},
	"csrf_token":    {},
}

func New(level string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:       slogLevel,
		ReplaceAttr: redactAttr,
	})
	return slog.New(handler)
}

func RedactKeyValue(key string, value any) any {
	if _, ok := sensitiveKeys[strings.ToLower(key)]; ok {
		return "[REDACTED]"
	}
	return value
}

func redactAttr(groups []string, attr slog.Attr) slog.Attr {
	_ = groups
	if _, ok := sensitiveKeys[strings.ToLower(attr.Key)]; ok {
		return slog.String(attr.Key, "[REDACTED]")
	}
	return attr
}
