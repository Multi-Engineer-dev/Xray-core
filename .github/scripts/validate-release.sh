#!/usr/bin/env bash
set -euo pipefail
official="${1:?usage: validate-release.sh OFFICIAL_CLIENT_DIRECTORY}"
test -s testing/scenarios/interop_test.go
go mod verify
go run ./infra/vformat/main.go -mode check -pwd ./
go build ./...
go test -timeout 1h ./...
go test -race -count=10 -timeout 15m ./proxy/shadowsocks_2022 ./app/proxyman/outbound
for tag in v25.12.8 v26.3.27 v26.10.21; do
  XRAY_UPSTREAM="$official/$tag/xray" go test -timeout 30m -count=1 -v -run '^TestUpstreamClient$' ./testing/scenarios
done
