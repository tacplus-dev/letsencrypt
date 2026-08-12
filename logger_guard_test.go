package main

import (
	"os"
	"strings"
	"testing"
)

// TestRunInstallsTheChassisLogger guards against reaching for a raw zap logger.
//
// letsencrypt holds the ACME account key and issues certificates, so its error
// paths carry exactly the material that must never reach a log. It called zap
// directly and had no credential redaction at all — the chassis is what wraps
// the sink in a redactor so a credential cannot escape through a structured
// FIELD, which message-level scrubbing does not catch.
//
// It is hand-written rather than generated, which is how it (and kmaker) missed
// the fleet-wide move to the chassis. Found by sweeping every go service for
// raw zap constructors after kmaker turned up the same bypass.
func TestRunInstallsTheChassisLogger(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	for _, ctor := range []string{"zap.NewProduction(", "zap.NewDevelopment(", "zap.NewExample("} {
		if strings.Contains(body, ctor) {
			t.Errorf("main.go uses %s, which performs no credential redaction; "+
				"use loggerchassis.InstallFromConfig", ctor)
		}
	}
	if !strings.Contains(body, "loggerchassis.InstallFromConfig") {
		t.Error("run() must install the chassis logger, which redacts structured fields")
	}
}
