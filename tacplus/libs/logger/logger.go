// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

import (
	"fmt"
	"os"

	"github.com/jinzhu/copier"
	protoerrors "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger represents a legacy logger configuration.
// This type is maintained for backward compatibility with existing code.
// For new code, consider using proto.LoggerConfig from the proto package instead.
//
// Fields:
//   - Format: Output format (JSON or console)
//   - Level: Minimum log level to output
//   - Development: Enable development mode features
//   - PrettyPrint: Enable pretty-printed JSON output
//   - ZapLogger: The underlying zap logger instance
//
// Internal fields (not serialized):
//   - formatLog: Internal format tracking
//   - logString: Buffer for delayed log messages
//   - installed: Tracks whether the logger has been installed
type Logger struct {
	Format      LogFormat `json:"format,omitempty" yaml:"format,omitempty"`
	Level       LogLevel  `json:"level,omitempty" yaml:"level,omitempty"`
	Development bool      `json:"development,omitempty" yaml:"development,omitempty"`
	formatLog   string
	logString   []string
	installed   bool
	ZapLogger   *zap.Logger `json:"-" yaml:"-"`
	PrettyPrint bool        `json:"prettyPrint,omitempty" yaml:"prettyPrint,omitempty"`
}

// Clone returns a deep copy of the Logger struct.
// This is useful when you need to create a new logger with modified settings
// without affecting the original logger instance.
//
// Returns nil if the receiver is nil.
//
// Example:
//
//	original := &Logger{Level: LogLevelDebug}
//	copy := original.Clone()
//	copy.Level = LogLevelInfo  // original is unchanged
func (x *Logger) Clone() *Logger {
	if x == nil {
		return nil
	}
	c := &Logger{}
	copier.Copy(&c, &x)
	return c
}

// Equals compares two Logger structs for equality.
// Only compares the configuration fields: Format, Level, and Development.
// Internal state fields (formatLog, logString, installed, ZapLogger, PrettyPrint) are ignored.
//
// Returns true if both loggers have the same configuration, even if they are different instances.
// Returns false if either logger is nil (unless both are nil or the same pointer).
//
// Example:
//
//	logger1 := &Logger{Format: LogFormatJson, Level: LogLevelInfo}
//	logger2 := &Logger{Format: LogFormatJson, Level: LogLevelInfo}
//	equal := logger1.Equals(logger2)  // Returns true
func (x *Logger) Equals(other *Logger) bool {
	// If both pointers are the same, they are equal
	if x == other {
		return true
	}
	// If one is nil, they are not equal
	if x == nil || other == nil {
		return false
	}

	// Compare only the configuration fields
	return x.Format == other.Format &&
		x.Level == other.Level &&
		x.Development == other.Development
}

// LogDelay buffers a log message to be output after the logger is installed.
// This is useful for logging events that occur during logger configuration,
// before the logger is fully set up and ready to use.
//
// Messages are stored internally and will be output as a debug log when Install() is called.
//
// Example:
//
//	logger := &Logger{}
//	logger.LogDelay("Starting configuration")
//	logger.LogDelay("Loading from environment")
//	logger.Install()  // Outputs: delayed log->["Starting configuration" "Loading from environment"]
func (x *Logger) LogDelay(s string) {
	x.logString = append(x.logString, s)
}

// LoadFromEnv loads configuration values from environment variables into the Logger struct.
// The mapping between struct fields and environment variables is defined in const.go.
//
// Environment variables read:
//   - CavalierLogLevel: Sets the Level field (trace, debug, info, warn, error)
//   - CavalierLogFormat: Sets the Format field (json, console)
//
// This function does not check if fields are already set, so it will overwrite
// existing values if the environment variables are present. Call this method
// before manually setting any fields if you want environment variables to take precedence.
//
// Returns an error if any environment variable has an invalid value.
//
// Example:
//
//	logger := &Logger{}
//	if err := logger.LoadFromEnv(); err != nil {
//	    log.Fatalf("Failed to load logger config: %v", err)
//	}
func (x *Logger) LoadFromEnv() error {

	{
		v := os.Getenv(LogFormatEnvVar)
		if v != "" {
			y, err := NewLogFormat(v)
			if err != nil {
				return protoerrors.NewErrMissingInvalidData(err, "env var %s=%s returned error", LogFormatEnvVar, v)
			}
			x.Format = y
			x.LogDelay(fmt.Sprintf("logger.Logger.Format=%s (env var %s)", v, LogFormatEnvVar))
		}
	}

	{
		v := os.Getenv(LogLevelEnvVar)
		if v != "" {
			y, err := NewLogLevel(v)
			if err != nil {
				return protoerrors.NewErrMissingInvalidData(err, "env var %s=%s returned error", LogLevelEnvVar, v)
			}
			x.Level = y
			x.LogDelay(fmt.Sprintf("logger.Logger.Level=%s (env var %s)", v, LogLevelEnvVar))
		}
	}

	return nil
}

// EnvVars returns a map of environment variable names to their values based on the Logger's current configuration.
// This is useful for passing logger configuration to child processes or for debugging.
//
// The mapping between struct fields and environment variables is defined in const.go:
//   - Format → CavalierLogFormat (if not undefined)
//   - Level → CavalierLogLevel (if not disabled)
//
// Only non-default values are included in the returned map.
//
// Example:
//
//	logger := &Logger{Format: LogFormatJson, Level: LogLevelDebug}
//	envVars := logger.EnvVars()
//	// envVars = {"CavalierLogFormat": "json", "CavalierLogLevel": "debug"}
func (x *Logger) EnvVars() map[string]string {

	m := make(map[string]string)

	if x.Format != LogFormatUndefined {
		m[LogFormatEnvVar] = LogFormatToString(x.Format)
	}

	if x.Level != LogLevelDisabled {
		m[LogLevelEnvVar] = LogLevelToString(x.Level)
	}

	return m
}

func (x *Logger) zapLevel() zapcore.Level {

	switch x.Level {

	case LogLevelTrace:
		isLogLevelTrace.Store(true)
		return zapcore.DebugLevel

	case LogLevelDebug:
		return zapcore.DebugLevel

	case LogLevelWarn:
		return zapcore.WarnLevel

	case LogLevelInfo:
		return zapcore.InfoLevel

	case LogLevelError:
		return zapcore.ErrorLevel

	}

	return defaultLogLevel
}

// Install configures and installs the logger as the global zap logger instance.
// This method should be called once during application initialization, typically in main().
//
// Behavior:
//   - Returns immediately if Level is LogLevelDisabled (no-op)
//   - Returns immediately if the logger is already installed (idempotent)
//   - Configures zap with the logger's Format, Level, Development, and PrettyPrint settings
//   - Replaces the global zap logger with the newly configured instance
//   - Outputs delayed log messages that were buffered before installation
//
// The logger will output to stderr by default.
//
// Panics if the zap logger cannot be built (e.g., invalid configuration).
//
// Example:
//
//	logger := &Logger{
//	    Format: LogFormatJson,
//	    Level: LogLevelInfo,
//	    Development: false,
//	}
//	logger.Install()
//	zap.L().Info("Logger installed successfully")
func (x *Logger) Install() {

	if x.Level == LogLevelDisabled {
		return
	}

	if x.installed {
		return
	}

	x.formatLog = fmt.Sprintf("logger.Format=%s (default)", x.Format)

	x.installed = true

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeCaller = zapcore.FullCallerEncoder

	zapConfig := &zap.Config{
		Development: x.Development,
		Sampling: &zap.SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:      defaultLoggerEncoding,
		EncoderConfig: encoderConfig,
		Level:         zap.NewAtomicLevelAt(x.zapLevel()),
	}

	if x.PrettyPrint {
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder // e.g., "2025-05-07T12:34:56.789Z"
	}

	zapConfig.OutputPaths = append(zapConfig.OutputPaths, "stderr")
	zapConfig.ErrorOutputPaths = append(zapConfig.ErrorOutputPaths, "stderr")

	setFormat := func() {

		switch x.Format {

		case LogFormatUndefined:
			zapConfig.Encoding = defaultLoggerEncoding

		case LogFormatConsole:
			zapConfig.Encoding = "console"

		default:
			zapConfig.Encoding = "json"

		}

	}

	setFormat()

	var err error
	x.ZapLogger, err = zapConfig.Build()
	if err != nil {
		panic(err)
	}

	zap.ReplaceGlobals(x.ZapLogger)

	zap.L().Debug(fmt.Sprintf("delayed log->[%s]", x.logString))
}
