# Local development builds only — not used in CI/CD.

TACPLUS := env_var_or_default("TACPLUS_BIN", "tacplus")

default: gates

# Regenerate model/ (not committed) with the compiler line tacplus.yaml pins.
# Generated code is never committed or edited by hand, so generation must
# leave every tracked file as it found it.
generate:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ -n "$(git ls-files model)" ]]; then
    echo "generate: model/ is generated and must not be committed" >&2; exit 1
  fi
  before="$(git diff HEAD | sha256sum)"
  {{TACPLUS}} build --tag latest
  if [[ "$(git diff HEAD | sha256sum)" != "$before" ]]; then
    echo "generate: tacplus build changed tracked files:" >&2; git status --short >&2; exit 1
  fi

# go.mod and go.sum must already be tidy for the generated code.
check-generated: generate
  #!/usr/bin/env bash
  set -euo pipefail
  before="$(cat go.mod go.sum | sha256sum)"
  go mod tidy
  if [[ "$(cat go.mod go.sum | sha256sum)" != "$before" ]]; then
    echo "check-generated: go.mod/go.sum are not tidy for the generated code (go mod tidy changed them)" >&2; exit 1
  fi

build: generate
  #!/usr/bin/env bash
  set -euo pipefail
  unformatted="$(gofmt -l main.go logger_guard_test.go internal)"
  if [[ -n "$unformatted" ]]; then
    echo "build: gofmt -l reports: $unformatted" >&2; exit 1
  fi
  go build ./...
  go vet ./...

test: build
  go test ./...

# The gates every change passes before it is pushed.
gates: check-generated test

clean:
  rm -rf model
