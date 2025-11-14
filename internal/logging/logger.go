// Copyright 2025 Gosayram Contributors
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

// Package logging provides structured logging functionality using zap.
package logging

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.Logger
type Logger struct {
	*zap.Logger
}

// New creates a new logger based on configuration
func New(level, format, outputPath string) (*Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zapLevel)

	if format == "text" {
		config.Encoding = "console"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		config.Encoding = "json"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	if outputPath != "" {
		config.OutputPaths = []string{outputPath}
		config.ErrorOutputPaths = []string{outputPath}
	}

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}

	return &Logger{Logger: logger}, nil
}

// NewNop returns a no-op logger
func NewNop() *Logger {
	return &Logger{Logger: zap.NewNop()}
}

// NewDevelopment returns a development logger
func NewDevelopment() (*Logger, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}
	return &Logger{Logger: logger}, nil
}

// WithFields adds structured fields to the logger
func (l *Logger) WithFields(fields ...zap.Field) *Logger {
	return &Logger{Logger: l.With(fields...)}
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// NewDefault creates a default logger for development
func NewDefault() *Logger {
	if os.Getenv("OPENKMS_LOG_LEVEL") == "" {
		logger, _ := NewDevelopment()
		return logger
	}
	logger, _ := New("info", "json", "")
	return logger
}
