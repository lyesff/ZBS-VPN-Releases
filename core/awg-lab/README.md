# AWG lab — first transport prototype (not yet in APK)

An isolated Go userspace prototype built against the official `amneziawg-go/v3`
module, pinned to `v3.1.20260828`. It creates its own **in-memory netstack**
(no Android VPN interface), configures a real AmneziaWG device via UAPI,
and confirms WARP with an HTTPS request through the tunnel.

This is not a finished Android feature, and no working WARP tunnel is claimed.
Before integration into AutoWARP:

1. Convert the **locally generated** AWG configuration into UAPI values;
   validate J/H/I obfuscation fields and leave secret keys in encrypted storage.
2. Provide an Android socket-binding mechanism (VpnService.protect) for AWG
   UDP sockets, or run standalone probes strictly before starting the VPN.
3. Choose a single owner for Android VpnService TUN; do not open competing TUN
   interfaces or switch engines while the old one is still active.
4. Add handshake and transfer counters, a bounded endpoint scan and real
   validation on a physical Android device.
5. Check the AWG third-party license and notices before distribution.

Run isolated tests with `cd core/awg-lab && go test -mod=mod ./...`.
`Probe` accepts raw UAPI settings only from trusted local configuration;
do not include sensitive settings in bug reports or diagnostics.
