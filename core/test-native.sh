#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${AUTOWARP_BUILD_DIR:-$root/.core-build}"
mkdir -p "$dir"
cd "$dir"
tar xzf "$root/core/sing-box-v1.13.12.tar.gz"
cd sing-box-1.13.12
cp "$root/core/profiles.go" "$root/core/control.go" experimental/libbox/
cp "$root/core/network_test.go" experimental/libbox/autowarp_network_test.go
cp "$root/core/profiles_test.go" experimental/libbox/autowarp_profiles_test.go
cp "$root/core/status.go" daemon/aw_status.go
extra=()
if [[ "${AUTOWARP_TEST_NO_NETLINK:-0}" == 1 ]]; then
    module=github.com/sagernet/wireguard-go
    go mod download "$module"
    source_dir="$(go list -m -f '{{.Dir}}' "$module")"
    copy="$(mktemp -d "$dir/wg-host-XXXXXX")"
    cp -R "$source_dir/." "$copy/"
    chmod u+w "$copy/conn/control_linux.go"
    sed -i 's/const StdNetSupportsStickySockets = true/const StdNetSupportsStickySockets = false/' "$copy/conn/control_linux.go"
    cp go.mod "$dir/host.mod"; cp go.sum "$dir/host.sum"
    go mod edit -modfile="$dir/host.mod" -replace="$module=$copy"
    extra+=("-modfile=$dir/host.mod")
fi
CGO_ENABLED=0 go test "${extra[@]}" -buildvcs=false -ldflags=-checklinkname=0 -tags with_gvisor,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0 -timeout=75s -v -run 'Test(Aw|Keys|RejectUnsafeOrUnsupported|Subscriptions|WireGuard$)' ./experimental/libbox
