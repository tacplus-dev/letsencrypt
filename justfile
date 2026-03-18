# Local development builds only — not used in CI/CD.

registry := "registry.gitlab.com/secondstarcavalier/controlplane/services/letsencrypt"

default: binary container

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -d "../proto" ]; then
    tacplus build --src ../proto
  else
    tacplus build
  fi

binary: generate
  go install -trimpath -ldflags="-s -w" .

container: generate
  #!/usr/bin/env bash
  set -euo pipefail
  tag=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
  major=$(echo "$tag" | cut -d. -f1)
  minor=$(echo "$tag" | cut -d. -f2)
  image="{{registry}}/letsencrypt-${major}-${minor}:latest"
  arch=$(uname -m)
  case "$arch" in
    x86_64)  goarch="amd64" ;;
    aarch64|arm64) goarch="arm64" ;;
    *) echo "unsupported arch: $arch"; exit 1 ;;
  esac
  mkdir -p bin
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "bin/letsencrypt-$goarch" .
  docker build --secret id=netrc,src=$HOME/.netrc -t "$image" .
  rm -rf bin
  echo "Built: $image"
