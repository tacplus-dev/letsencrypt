// Copyright (c) 2024 Second Star Cavalier, LLC.

// Package logger provides utilities for configuring and managing structured logging in Go applications.
//
// This package offers two approaches to logger configuration:
//   1. Legacy Logger struct (backward compatible with existing code)
//   2. Proto-based LoggerConfig (recommended for new code, uses protocol buffers)
//
// Both approaches ultimately configure and install a global zap logger instance
// that can be accessed via zap.L() throughout your application.
//
// # Key Features
//
//   - Multiple output formats (JSON for production, Console for development)
//   - Configurable log levels (Trace, Debug, Info, Warn, Error)
//   - Environment variable-based configuration
//   - Development and production modes
//   - Pretty-printing option for JSON logs
//   - Delayed logging for messages before logger initialization
//   - Trace level optimization checks
//
// # Basic Usage - Legacy Logger
//
// Using the legacy Logger struct:
//
//	logger := &logger.Logger{
//	    Format: logger.LogFormatJson,
//	    Level: logger.LogLevelInfo,
//	    Development: false,
//	}
//	logger.Install()
//	zap.L().Info("Application started")
//
// Loading from environment variables:
//
//	logger := &logger.Logger{}
//	if err := logger.LoadFromEnv(); err != nil {
//	    log.Fatalf("Failed to load logger config: %v", err)
//	}
//	logger.Install()
//
// # Basic Usage - Proto Logger
//
// Using the proto-based LoggerConfig (recommended):
//
//	config := &proto.LoggerConfig{
//	    Format: proto.Format_FORMAT_JSON,
//	    Level: proto.Level_LEVEL_INFO,
//	    Development: false,
//	    OutputPaths: []string{"stdout", "/var/log/app.log"},
//	    InitialFields: map[string]string{
//	        "service": "api",
//	        "version": "1.0.0",
//	    },
//	}
//	logger, err := logger.InstallFromConfig(config)
//	if err != nil {
//	    log.Fatalf("Failed to install logger: %v", err)
//	}
//
// Loading proto config from environment:
//
//	config := &proto.LoggerConfig{}
//	if err := logger.LoadFromEnv(config); err != nil {
//	    log.Fatalf("Failed to load config: %v", err)
//	}
//	logger, err := logger.InstallFromConfig(config)
//
// # Environment Variables
//
// The package reads configuration from the following environment variables:
//   - CavalierLogLevel: Log level (trace, debug, info, warn, error)
//   - CavalierLogFormat: Log format (json, console)
//
// Example:
//
//	export CavalierLogLevel=debug
//	export CavalierLogFormat=console
//
// # Log Levels
//
// Log levels in order of increasing severity:
//   - Trace: Most verbose, detailed debugging (mapped to Debug in zap)
//   - Debug: Debugging information
//   - Info: Informational messages about normal operations
//   - Warn: Warning messages about potentially problematic situations
//   - Error: Error messages about failures and problems
//
// # Log Formats
//
// Available output formats:
//   - JSON: Structured logs as JSON objects, ideal for log aggregation systems
//   - Console: Human-readable logs, ideal for development and debugging
//
// # Development vs Production Mode
//
// Development mode enables:
//   - Console format by default
//   - Stack traces for warnings and errors
//   - More human-readable timestamps
//   - Full caller information (file:line)
//
// Production mode enables:
//   - JSON format by default
//   - Minimal overhead
//   - Sampling to reduce high-frequency log spam
//
// # Trace Level Optimization
//
// Use IsLogLevelTrace() to conditionally execute expensive logging operations:
//
//	if logger.IsLogLevelTrace() {
//	    data := generateExpensiveDebugData()
//	    zap.L().Debug("Trace data", zap.Any("data", data))
//	}
//
// # Converting Between Legacy and Proto Types
//
// Convert legacy Logger to proto LoggerConfig:
//
//	legacyLogger := &logger.Logger{Format: logger.LogFormatJson}
//	config := logger.ConvertLegacyToProto(legacyLogger)
//
// Convert proto LoggerConfig to legacy Logger:
//
//	config := &proto.LoggerConfig{Format: proto.Format_FORMAT_JSON}
//	legacyLogger := logger.ConvertProtoToLegacy(config)
//
// # Advanced Configuration (Proto Only)
//
// The proto-based configuration supports additional options:
//
//	config := &proto.LoggerConfig{
//	    Format: proto.Format_FORMAT_JSON,
//	    Level: proto.Level_LEVEL_INFO,
//	    PrettyPrint: true,  // Pretty-print JSON (development only)
//	    OutputPaths: []string{"stdout", "/var/log/app.log"},
//	    ErrorOutputPaths: []string{"stderr", "/var/log/app-errors.log"},
//	    DisableCaller: false,  // Include caller info
//	    DisableStacktrace: false,  // Include stacktraces for errors
//	    Encoding: "json",  // Override format-based encoding
//	    InitialFields: map[string]string{
//	        "service": "api",
//	        "version": "1.0.0",
//	        "environment": "production",
//	    },
//	}
//
// # Parsing Log Events
//
// Parse zap JSON log output:
//
//	var event logger.ZapLogEvent
//	if err := json.Unmarshal([]byte(logLine), &event); err != nil {
//	    log.Printf("Failed to parse log: %v", err)
//	}
//	timestamp := event.GetTime()
//	formattedTime := event.GetTimeWithDefaultFormat("")
//
// # Best Practices
//
//  1. Install the logger early in main() before other initialization
//  2. Use JSON format in production for structured logging
//  3. Use Console format in development for readability
//  4. Set appropriate log levels (Info for production, Debug for development)
//  5. Use InitialFields to add context to all log messages
//  6. Use IsLogLevelTrace() to guard expensive trace operations
//  7. Prefer proto.LoggerConfig for new code (more features, better validation)
//  8. Load configuration from environment variables for flexibility
//
// # Migration from Legacy to Proto
//
// To migrate existing code:
//
//  1. Replace Logger with proto.LoggerConfig
//  2. Replace LogLevel constants with proto.Level enum values
//  3. Replace LogFormat constants with proto.Format enum values
//  4. Replace Install() with InstallFromConfig()
//  5. Use ConvertLegacyToProto() as a temporary bridge if needed
//
// Example migration:
//
//	// Before (legacy)
//	logger := &logger.Logger{
//	    Format: logger.LogFormatJson,
//	    Level: logger.LogLevelInfo,
//	}
//	logger.Install()
//
//	// After (proto)
//	config := &proto.LoggerConfig{
//	    Format: proto.Format_FORMAT_JSON,
//	    Level: proto.Level_LEVEL_INFO,
//	}
//	logger.InstallFromConfig(config)
package logger
