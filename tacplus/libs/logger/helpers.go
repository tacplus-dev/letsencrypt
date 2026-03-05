// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	loggerProto "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/logger"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/errors"
)

// LoadFromEnv loads logger configuration from environment variables into the provided LoggerConfig proto message.
// It reads values from environment variables prefixed with "Cavalier" and
// populates the provided LoggerConfig proto message.
//
// Environment variables:
//   - CavalierLogLevel: string - Log level (trace, debug, info, warn, error)
//   - CavalierLogFormat: string - Log format (json, console)
//
// Example:
//
//	config := &proto.LoggerConfig{}
//	if err := LoadFromEnv(config); err != nil {
//	    log.Fatalf("Failed to load config: %v", err)
//	}
func LoadFromEnv(config *loggerProto.LoggerConfig) error {

	var errs *multierror.Error

	// Load Level (enum)
	{
		v := os.Getenv(LogLevelEnvVar)
		if v != "" {
			level, err := loggerProto.ParseLevel(v)
			if err != nil {
				errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "env var %s=%s is invalid", LogLevelEnvVar, v))
			} else {
				config.Level = level
				zap.L().Debug(fmt.Sprintf("config.Level=%s (env var %s)", level, LogLevelEnvVar))
			}
		}
	}

	// Load Format (enum)
	{
		v := os.Getenv(LogFormatEnvVar)
		if v != "" {
			format, err := loggerProto.ParseFormat(v)
			if err != nil {
				errs = multierror.Append(errs, protoerrors.NewErrMissingInvalidData(err, "env var %s=%s is invalid", LogFormatEnvVar, v))
			} else {
				config.Format = format
				zap.L().Debug(fmt.Sprintf("config.Format=%s (env var %s)", format, LogFormatEnvVar))
			}
		}
	}

	return errs.ErrorOrNil()
}

// LevelToZapLevel converts a proto.Level to a zapcore.Level.
// This is used internally to configure the zap logger with the correct level.
//
// Mapping:
//   - LEVEL_TRACE → zapcore.DebugLevel (zap doesn't have a separate trace level)
//   - LEVEL_DEBUG → zapcore.DebugLevel
//   - LEVEL_INFO → zapcore.InfoLevel
//   - LEVEL_WARN → zapcore.WarnLevel
//   - LEVEL_ERROR → zapcore.ErrorLevel
//   - LEVEL_UNDEFINED → zapcore.InfoLevel (default)
func LevelToZapLevel(level loggerProto.Level) zapcore.Level {
	switch level {
	case loggerProto.Level_LEVEL_TRACE:
		isLogLevelTrace.Store(true)
		return zapcore.DebugLevel
	case loggerProto.Level_LEVEL_DEBUG:
		return zapcore.DebugLevel
	case loggerProto.Level_LEVEL_INFO:
		return zapcore.InfoLevel
	case loggerProto.Level_LEVEL_WARN:
		return zapcore.WarnLevel
	case loggerProto.Level_LEVEL_ERROR:
		return zapcore.ErrorLevel
	}
	return defaultLogLevel
}

// FormatToEncoding converts a proto.Format to a zap encoder name string.
// This is used internally to configure the zap logger with the correct encoding.
//
// Mapping:
//   - FORMAT_JSON → "json"
//   - FORMAT_CONSOLE → "console"
//   - FORMAT_UNDEFINED → "json" (default)
func FormatToEncoding(format loggerProto.Format) string {
	switch format {
	case loggerProto.Format_FORMAT_JSON:
		return "json"
	case loggerProto.Format_FORMAT_CONSOLE:
		return "console"
	case loggerProto.Format_FORMAT_UNDEFINED:
		return defaultLoggerEncoding
	}
	return defaultLoggerEncoding
}

// InstallFromConfig installs a global zap logger based on the provided LoggerConfig proto message.
// It configures the logger with all settings from the config and replaces the global zap logger.
//
// Configuration applied:
//   - Format (JSON or console)
//   - Level (trace, debug, info, warn, error)
//   - Development mode settings
//   - Pretty printing for JSON
//   - Output paths (stdout, stderr, file paths)
//   - Error output paths
//   - Caller information inclusion
//   - Stacktrace settings
//   - Initial fields added to every log entry
//
// Example:
//
//	config := &proto.LoggerConfig{
//	    Format: proto.Format_FORMAT_JSON,
//	    Level: proto.Level_LEVEL_DEBUG,
//	    Development: true,
//	    OutputPaths: []string{"stdout"},
//	}
//	logger, err := InstallFromConfig(config)
//	if err != nil {
//	    log.Fatalf("Failed to install logger: %v", err)
//	}
func InstallFromConfig(config *loggerProto.LoggerConfig) (*zap.Logger, error) {
	if config == nil {
		config = &loggerProto.LoggerConfig{}
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder

	// Apply pretty printing for timestamps if requested
	if config.PrettyPrint {
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Set encoding based on format
	encoding := FormatToEncoding(config.Format)

	zapConfig := &zap.Config{
		Development: config.Development,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:          encoding,
		EncoderConfig:     encoderConfig,
		Level:             zap.NewAtomicLevelAt(LevelToZapLevel(config.Level)),
		OutputPaths:       config.OutputPaths,
		ErrorOutputPaths:  config.ErrorOutputPaths,
		DisableCaller:     config.DisableCaller,
		DisableStacktrace: config.DisableStacktrace,
	}

	// Set default output paths if not specified
	if len(zapConfig.OutputPaths) == 0 {
		zapConfig.OutputPaths = []string{"stderr"}
	}
	if len(zapConfig.ErrorOutputPaths) == 0 {
		zapConfig.ErrorOutputPaths = []string{"stderr"}
	}

	// Build the logger
	logger, err := zapConfig.Build()
	if err != nil {
		return nil, protoerrors.NewErrGeneral(err, "failed to build logger")
	}

	// Add initial fields if specified
	if len(config.InitialFields) > 0 {
		fields := make([]zap.Field, 0, len(config.InitialFields))
		for key, value := range config.InitialFields {
			fields = append(fields, zap.String(key, value))
		}
		logger = logger.With(fields...)
	}

	// Replace global logger
	zap.ReplaceGlobals(logger)

	defer logger.Sync()

	return logger, nil
}

// ConvertLegacyToProto converts a legacy Logger struct to a proto.LoggerConfig message.
// This is useful for migrating from the old Logger type to the new proto-based configuration.
//
// Fields converted:
//   - Format (LogFormat → proto.Format)
//   - Level (LogLevel → proto.Level)
//   - Development (bool → bool)
//   - PrettyPrint (bool → bool)
//
// Example:
//
//	legacyLogger := &Logger{
//	    Format: LogFormatJson,
//	    Level: LogLevelDebug,
//	    Development: true,
//	}
//	config := ConvertLegacyToProto(legacyLogger)
func ConvertLegacyToProto(legacy *Logger) *loggerProto.LoggerConfig {
	if legacy == nil {
		return nil
	}

	config := &loggerProto.LoggerConfig{
		Development: legacy.Development,
		PrettyPrint: legacy.PrettyPrint,
	}

	// Convert format
	switch legacy.Format {
	case LogFormatJson:
		config.Format = loggerProto.Format_FORMAT_JSON
	case LogFormatConsole:
		config.Format = loggerProto.Format_FORMAT_CONSOLE
	default:
		config.Format = loggerProto.Format_FORMAT_UNDEFINED
	}

	// Convert level
	switch legacy.Level {
	case LogLevelTrace:
		config.Level = loggerProto.Level_LEVEL_TRACE
	case LogLevelDebug:
		config.Level = loggerProto.Level_LEVEL_DEBUG
	case LogLevelInfo:
		config.Level = loggerProto.Level_LEVEL_INFO
	case LogLevelWarn:
		config.Level = loggerProto.Level_LEVEL_WARN
	case LogLevelError:
		config.Level = loggerProto.Level_LEVEL_ERROR
	default:
		config.Level = loggerProto.Level_LEVEL_UNDEFINED
	}

	return config
}

// ConvertProtoToLegacy converts a proto.LoggerConfig message to a legacy Logger struct.
// This is useful for backward compatibility with code that uses the old Logger type.
//
// Fields converted:
//   - Format (proto.Format → LogFormat)
//   - Level (proto.Level → LogLevel)
//   - Development (bool → bool)
//   - PrettyPrint (bool → bool)
//
// Example:
//
//	config := &proto.LoggerConfig{
//	    Format: proto.Format_FORMAT_JSON,
//	    Level: proto.Level_LEVEL_DEBUG,
//	}
//	legacyLogger := ConvertProtoToLegacy(config)
func ConvertProtoToLegacy(config *loggerProto.LoggerConfig) *Logger {
	if config == nil {
		return nil
	}

	legacy := &Logger{
		Development: config.Development,
		PrettyPrint: config.PrettyPrint,
	}

	// Convert format
	switch config.Format {
	case loggerProto.Format_FORMAT_JSON:
		legacy.Format = LogFormatJson
	case loggerProto.Format_FORMAT_CONSOLE:
		legacy.Format = LogFormatConsole
	default:
		legacy.Format = LogFormatUndefined
	}

	// Convert level
	switch config.Level {
	case loggerProto.Level_LEVEL_TRACE:
		legacy.Level = LogLevelTrace
	case loggerProto.Level_LEVEL_DEBUG:
		legacy.Level = LogLevelDebug
	case loggerProto.Level_LEVEL_INFO:
		legacy.Level = LogLevelInfo
	case loggerProto.Level_LEVEL_WARN:
		legacy.Level = LogLevelWarn
	case loggerProto.Level_LEVEL_ERROR:
		legacy.Level = LogLevelError
	default:
		legacy.Level = LogLevelDisabled
	}

	return legacy
}
