proto_dir := "../proto"
proto_repo := "git@gitlab.com:secondstarcavalier/controlplane/services/proto.git"

build:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -d "{{proto_dir}}" ]; then
    echo "Cloning proto..."
    git clone {{proto_repo}} {{proto_dir}}
  fi
  tacplus build -c tacplus-local.yaml
  go build -ldflags="-s -w" ./...
  docker build --secret id=netrc,src=$HOME/.netrc -t $(basename $PWD) .
