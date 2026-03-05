// Copyright (c) 2024 Second Star Cavalier, LLC.

package logger

import "sync/atomic"

// This global variable tracks whether TRACE level logging is enabled.
// It can only be set within this package but can be read globally.
// This is used as an optimization to avoid expensive trace logging operations
// when trace level is not enabled.
// Access is synchronized via sync/atomic to prevent data races.
var isLogLevelTrace atomic.Bool

// IsLogLevelTrace returns true if TRACE level logging is globally enabled.
// This function can be used to conditionally execute expensive logging operations
// only when trace logging is active.
//
// Example:
//
//	if logger.IsLogLevelTrace() {
//	    // Perform expensive operation only when trace logging is enabled
//	    data := generateDetailedDebugInfo()
//	    zap.L().Debug("Detailed trace info", zap.Any("data", data))
//	}
func IsLogLevelTrace() bool {
	return isLogLevelTrace.Load()
}
