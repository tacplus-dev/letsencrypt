# Local development builds only — not used in CI/CD.

TACPLUS_IMAGE := "registry.gitlab.com/secondstarcavalier/schematic/tacplus/tacplus-1-2:latest"

default: generate

generate:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -d proto ]; then
    git -C proto fetch --quiet
    git -C proto reset --hard --quiet origin/HEAD
  else
    git clone --quiet https://gitlab.com/secondstarcavalier/schematic/platform/proto.git proto
  fi
  docker pull "{{TACPLUS_IMAGE}}" --quiet
  docker run --rm \
    -v "$PWD:/work" \
    -w /work \
    "{{TACPLUS_IMAGE}}" \
    tacplus build --src proto
