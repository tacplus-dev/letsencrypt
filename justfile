build:
  tacplus build
  go build -ldflags="-s -w" ./...
  docker build --secret id=netrc,src=$HOME/.netrc -t $(basename $PWD) .
