# tink

[![CI](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml) [![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/hybridgroup/tink/badges/coverage.json)](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml)

<p align="center"><img src="images/tink-gopher.png" alt="tink gopher" width="400"></p>

Go and TinyGo packages for tiny devices to join [wendy-net](https://docs.wendy.dev/latest/guides/wendy-net/) wireless mesh networks based on the [Wendy](https://wendy.dev/) platform for robotics and physical AI.

Runs on boards with Espressif `esp32c3` and `esp32s3` processors.

## Quick Start

You must have the latest development version of TinyGo installed.

You also must have the needed Wendy device credentials to authenticate to wendy-net.

```
tinygo flash -target xiao-esp32c3 -ldflags="-X main.ssid=SSID -X main.password=PASS" -monitor ./examples/wendynet-wifi
```

## Examples

- wendynet-display
- wendynet-wifi

## Development

Use a `go.work` file to point at local checkouts of lcrypto, lneto and espradio.

```
go work init .
go work use ../../tinygo/lcrypto ../../tinygo/lneto ../../tinygo/espradio
```

## Testing

```
go test ./pkg/...
tinygo test ./pkg/...
```

## Leaf session

`pkg/link` follows the session in wendy-lite `components/wendy_net_peer/src/peer.c` and `router_session.c`.

1. Both sides send the hello preamble and check the other's.
2. The leaf describes its certificate chain and announces its signed manifest with gossip HAVE. The router fetches it with WANT.
3. Babel Hello, IHU and Update keep the link and the leaf /128 route up. Lite accepts the route once its routerId and seqno match the manifest.
4. IPv6 packets travel as fragment datagrams.

## Testing against wendy-lite

`internal/liteinterop` runs tink against wendy-lite's C code built for the host. See its README.md.
