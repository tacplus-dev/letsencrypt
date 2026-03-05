// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

import (
	loggerProto "gitlab.com/secondstarcavalier/controlplane/services/letsencrypt/tacplus/types/libs/logger"
)

// LogLevel is an alias for the proto-generated Level enum.
// Use the Level_* constants from the proto package.
type LogLevel = loggerProto.Level

// LogLevel constants (aliases to proto-generated values)
const (
	LogLevelDisabled = loggerProto.Level_LEVEL_UNDEFINED
	LogLevelTrace    = loggerProto.Level_LEVEL_TRACE
	LogLevelDebug    = loggerProto.Level_LEVEL_DEBUG
	LogLevelInfo     = loggerProto.Level_LEVEL_INFO
	LogLevelWarn     = loggerProto.Level_LEVEL_WARN
	LogLevelError    = loggerProto.Level_LEVEL_ERROR
)

// LogFormat is an alias for the proto-generated Format enum.
// Use the Format_* constants from the proto package.
type LogFormat = loggerProto.Format

// LogFormat constants (aliases to proto-generated values)
const (
	LogFormatUndefined = loggerProto.Format_FORMAT_UNDEFINED
	LogFormatJson      = loggerProto.Format_FORMAT_JSON
	LogFormatConsole   = loggerProto.Format_FORMAT_CONSOLE
)

// NewLogLevel creates a LogLevel from a string value.
// It accepts case-insensitive strings: "trace", "debug", "info", "warn", "error".
// An empty string returns LogLevelDisabled.
//
// Returns an error if the string is not a valid log level.
//
// Example:
//
//	level, err := NewLogLevel("debug")  // Returns LogLevelDebug, nil
//	level, err := NewLogLevel("DEBUG")  // Returns LogLevelDebug, nil (case-insensitive)
//	level, err := NewLogLevel("invalid")  // Returns LogLevelDisabled, error
func NewLogLevel(s string) (LogLevel, error) {
	return loggerProto.ParseLevel(s)
}

// LogLevelValues returns all the possible LogLevel values.
//
// Returns: []LogLevel containing all valid log levels
func LogLevelValues() []LogLevel {
	return loggerProto.LevelValues()
}

// LogLevelStringValues returns all the possible LogLevel values as strings.
// This is useful for generating help text, validation messages, or UI dropdowns.
//
// Returns: []string{"trace", "debug", "info", "warn", "error"}
func LogLevelStringValues() []string {
	return loggerProto.LevelStringValues()
}

// LogLevelPointer returns a pointer to the given LogLevel value.
// This is useful when you need to pass a LogLevel by pointer.
//
// Example:
//
//	level := LogLevelDebug
//	ptr := LogLevelPointer(level)  // Returns *LogLevel pointing to LogLevelDebug
func LogLevelPointer(x LogLevel) *LogLevel {
	return &x
}

// LogLevelToString converts a LogLevel to its lowercase string representation.
// Returns the simple lowercase name (e.g., "debug", "info", "warn", "error", "trace").
// Returns an empty string for LogLevelDisabled.
//
// Example:
//
//	str := LogLevelToString(LogLevelDebug)  // Returns "debug"
func LogLevelToString(level LogLevel) string {
	switch level {
	case LogLevelTrace:
		return "trace"
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo:
		return "info"
	case LogLevelWarn:
		return "warn"
	case LogLevelError:
		return "error"
	default:
		return ""
	}
}

// NewLogFormat creates a LogFormat from a string value.
// It accepts case-insensitive strings: "json", "js", "console", "con".
// An empty string returns LogFormatUndefined.
//
// Returns an error if the string is not a valid log format.
//
// Example:
//
//	format, err := NewLogFormat("json")  // Returns LogFormatJson, nil
//	format, err := NewLogFormat("js")  // Returns LogFormatJson, nil (shorthand)
//	format, err := NewLogFormat("console")  // Returns LogFormatConsole, nil
//	format, err := NewLogFormat("invalid")  // Returns LogFormatUndefined, error
func NewLogFormat(s string) (LogFormat, error) {
	// Handle shorthands before passing to proto parser
	switch s {
	case "js", "JS", "Js", "jS":
		s = "json"
	case "con", "CON", "Con", "cOn", "coN", "COn", "cON", "CoN":
		s = "console"
	}
	return loggerProto.ParseFormat(s)
}

// LogFormatValues returns all the possible LogFormat values.
//
// Returns: []LogFormat containing all valid formats
func LogFormatValues() []LogFormat {
	return loggerProto.FormatValues()
}

// LogFormatStringValues returns all the possible LogFormat values as strings.
// This is useful for generating help text, validation messages, or UI dropdowns.
//
// Returns: []string{"json", "console"}
func LogFormatStringValues() []string {
	return loggerProto.FormatStringValues()
}

// LogFormatToString converts a LogFormat to its lowercase string representation.
// Returns the simple lowercase name (e.g., "json", "console").
// Returns an empty string for LogFormatUndefined.
//
// Example:
//
//	str := LogFormatToString(LogFormatJson)  // Returns "json"
func LogFormatToString(format LogFormat) string {
	switch format {
	case LogFormatJson:
		return "json"
	case LogFormatConsole:
		return "console"
	default:
		return ""
	}
}
