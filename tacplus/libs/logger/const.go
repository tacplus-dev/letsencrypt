// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

/*
This file defines logging constants including environment variable names for
configuring log level and format, as well as default values for the logger.
*/

import (
	"go.uber.org/zap/zapcore"
)

const (
	kindPrepend = "Cavalier"

	// LogLevelEnvVar is the environment variable name for configuring the log level.
	// Set this to one of: trace, debug, info, warn, error.
	// Example: export CavalierLogLevel=debug
	LogLevelEnvVar = kindPrepend + "LogLevel"

	// LogFormatEnvVar is the environment variable name for configuring the log format.
	// Set this to one of: json, console.
	// Example: export CavalierLogFormat=console
	LogFormatEnvVar = kindPrepend + "LogFormat"

	defaultLogLevel       = zapcore.InfoLevel
	defaultLoggerEncoding = "json"

	// DefaultTimeFormat is the default time format used for formatting log timestamps.
	// Format: "2006-01-02 15:04:05" (YYYY-MM-DD HH:MM:SS)
	DefaultTimeFormat = "2006-01-02 15:04:05"
)
