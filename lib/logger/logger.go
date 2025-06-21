package logger

import (
	"log/slog"

	"github.com/dgraph-io/badger/v4"
)

type BadgerLogger struct {
	lgr *slog.Logger
}

func (l BadgerLogger) Errorf(format string, args ...interface{}) {
	l.lgr.Error(format, args...)
}
func (l BadgerLogger) Infof(format string, args ...interface{}) {
	l.lgr.Info(format, args...)
}
func (l BadgerLogger) Debugf(format string, args ...interface{}) {
	l.lgr.Debug(format, args...)
}
func (l BadgerLogger) Warningf(format string, args ...interface{}) {
	l.lgr.Warn(format, args...)
}

func AdaptLoggerToBadgerLogger(lgr *slog.Logger) badger.Logger {
	return &BadgerLogger{
		lgr: lgr,
	}
}
