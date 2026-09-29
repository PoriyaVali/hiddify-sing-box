# hiddify-sing-box — Doctor Mobile core

The sing-box core of the Doctor Mobile apps. It is derived from hiddify's fork
and follows upstream [sing-box](https://github.com/SagerNet/sing-box).

- **Current base:** sing-box **1.13.21**.
- **Branch:** `doctormobile/bump-v1.13.15`. `main` follows it.
- **Android, iOS and desktop apps** use this core through
  [hiddify-core](https://github.com/PoriyaVali/hiddify-core) (libcore), which
  pins a commit of this repository.
- **Routers and command-line use** take the `sing-box` binaries from
  [Releases](https://github.com/PoriyaVali/hiddify-sing-box/releases). A
  `cli-*` tag builds them for:
  - Windows: amd64, arm64
  - Linux: amd64, arm64, armv7, mips and mipsle (softfloat)

## What's new in cli-v1.13.21-dm (2026-09-29)

Updated from sing-box 1.13.15 to the fixes in 1.13.21 (#1).

- **AnyTLS:** the client no longer sends its software name and version to the
  server. A new `client_metadata` option sets a value if one is needed.
  AnyTLS URLTest results are fixed.
- **URLTest and delay tests:** an outbound that never answers now reports
  "Timeout" when the requested timeout runs out. It used to hang for 30 s or
  more, and URLTest groups stalled on it.
- **WebSocket:** early data works with smux and yamux multiplexing. A failed
  handshake no longer panics.
- **Rule sets:** malformed `.srs`, geosite or profile data now gives an error
  instead of a panic or unbounded memory use.
- **cache.db:** a corrupted cache no longer crashes the core, at start or while
  running. It starts with an empty cache.
- **DNS:** address matching for inverted rules and DHCP DNS search domains are
  fixed.
- **Routing and TUN:** these are fixed:
  - loopback protection and a routing loop on darwin;
  - duplicated `route_address_set` IP sets;
  - FakeIP metadata saving;
  - network reset;
  - log output before start;
  - slow-open connections.
- **Dependencies:**
  - sing 0.8.14;
  - sing-quic 0.6.5;
  - sing-tun 0.8.15, which fixes gVisor keepalive traffic, the default
    interface monitor on boot, TCP NAT port reuse, system-stack panics and
    the `su` lookup for Android auto_redirect.

## Doctor Mobile changes on top of sing-box

- **Mirage:** TLS-record fragmentation shaped to get past SNI-based DPI,
  REALITY included.
- **TLS handshake timeout:** 60 s, for slow and lossy networks.
- **Kept from hiddify:**
  - WARP
  - the xray outbound, which provides XHTTP and others
  - extended WireGuard options
  - unified delay
- **Removed:** dnstt, mieru, psiphon and tunnel. The apps do not use them.

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
