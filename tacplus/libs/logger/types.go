// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

import (
	"time"
)

// ZapLogEvent represents a log event from zap logger in JSON format.
// This struct is used for parsing and analyzing zap's JSON log output.
//
// Fields:
//   - Level: The log level (debug, info, warn, error)
//   - Ts: Unix timestamp with fractional seconds
//   - Caller: The file and line number where the log was generated
//   - Msg: The log message content
//
// Example JSON:
//
//	{"level":"info","ts":1640000000.123,"caller":"main.go:42","msg":"Application started"}
type ZapLogEvent struct {
	Level  string  `json:"level,omitempty" yaml:"level,omitempty"`
	Ts     float64 `json:"ts,omitempty" yaml:"ts,omitempty"`
	Caller string  `json:"caller,omitempty" yaml:"caller,omitempty"`
	Msg    string  `json:"msg,omitempty" yaml:"msg,omitempty"`
}

// GetTime returns the time of the event as a time.Time value.
// It converts the Unix timestamp with fractional seconds stored in Ts
// into a proper Go time.Time object.
//
// Example:
//
//	event := &ZapLogEvent{Ts: 1640000000.123456789}
//	t := event.GetTime()  // Returns time.Time for 2021-12-20 13:33:20.123456789
func (x *ZapLogEvent) GetTime() time.Time {
	s := int64(x.Ts)
	n := int64((x.Ts - float64(s)) * 1e9)
	return time.Unix(s, n)
}

// GetTimeWithDefaultFormat returns the time of the event formatted as a string.
// It uses DefaultTimeFormat ("2006-01-02 15:04:05") to format the timestamp.
// The format parameter is currently ignored and DefaultTimeFormat is always used.
//
// Example:
//
//	event := &ZapLogEvent{Ts: 1640000000.123}
//	formatted := event.GetTimeWithDefaultFormat("")  // Returns "2021-12-20 13:33:20"
func (x *ZapLogEvent) GetTimeWithDefaultFormat(format string) string {
	return x.GetTime().Format(DefaultTimeFormat)
}
