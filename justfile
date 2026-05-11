# Local development builds only — not used in CI/CD.

proto-sync:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ -L proto ]; then
    : # symlink — user-managed, skip sync
  elif [ -d proto ]; then
    git -C proto fetch --quiet
    git -C proto reset --hard --quiet origin/HEAD
  else
    git clone --quiet https://gitlab.com/secondstarcavalier/schematic/platform/proto.git proto
  fi

default: proto-sync
  tacplus build --src proto
