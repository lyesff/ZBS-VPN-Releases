#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${AUTOWARP_BUILD_DIR:-$root/.core-build}"
mkdir -p "$dir" "$root/app/libs"
# The original source archive is not committed. Fetch the versioned upstream tag.
# For stronger supply-chain pinning, replace the tag with a reviewed commit SHA.
if [ ! -d "$dir/sing-box/.git" ]; then
  git clone --depth 1 --branch v1.13.12 https://github.com/SagerNet/sing-box.git "$dir/sing-box"
fi
cd "$dir/sing-box"
test "$(git describe --tags --exact-match HEAD)" = "v1.13.12"
cp "$root/core/profiles.go" "$root/core/control.go" experimental/libbox/
cp "$root/core/status.go" daemon/aw_status.go
# Single gomobile binding is required: two independent Go AARs both bundle
# go.Seq and cannot coexist in one Android APK.
go mod tidy
go mod edit -replace=dev.autowarp/awg-lab="$root/core/awg-lab"
go get dev.autowarp/awg-lab
go install github.com/sagernet/gomobile/cmd/gomobile github.com/sagernet/gomobile/cmd/gobind
export PATH="$(go env GOPATH)/bin:$PATH" GOFLAGS="-buildvcs=false -p=4"
gomobile init
# Optional CI-only emulator target; normal APK builds remain ARM64.
targets="${AUTOWARP_GOMOBILE_TARGETS:-android/arm64}"
case "$targets" in
  android/arm64|android/amd64) ;;
  *) echo "Unsupported AutoWARP mobile target" >&2; exit 1 ;;
esac
gomobile bind -target "$targets" -androidapi 29 -javapkg=io.nekohasekai -libname=box -tags with_gvisor,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0 -ldflags="-s -w -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version=1.13.12" -o "$root/app/libs/libbox.aar" ./experimental/libbox dev.autowarp/awg-lab
