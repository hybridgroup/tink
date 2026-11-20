# tink

[![CI](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml) [![coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/hybridgroup/tink/badges/coverage.json)](https://github.com/hybridgroup/tink/actions/workflows/ci.yaml)

<p align="center"><img src="images/tink-gopher.png" alt="tink gopher" width="400"></p>

Go and TinyGo packages for tiny devices to join [wendy-net](https://docs.wendy.dev/latest/guides/wendy-net/) wireless mesh networks based on the [Wendy](https://wendy.dev/) platform for robotics and physical AI.

Runs on boards with Espressif `esp32`, `esp32c3`, `esp32c6` and `esp32s3` processors. Tested with these TinyGo targets.

- `esp32-coreboard-v2`
- `xiao-esp32c3`
- `xiao-esp32c6`
- `xiao-esp32s3`

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

## Host router for board testing

A board running `examples/wendynet-wifi` can join a Lite router running on your computer.

1. Build `router_tls_fixture` as described in `internal/liteinterop/README.md`.
2. Create a test tenant root with router and board credentials. They are valid for 30 days.

```
go run ./internal/liteinterop/testcreds internal/liteinterop/router/build/hw examples/wendynet-wifi/creds
```

   This writes `root.der`, `router-cert.der` and `router-key.der` for the router, and `tenant-root.der`, `device-cert.der` and `device-key.der` for the board. It refuses to overwrite existing files, so move any real board credentials out of `creds/` first.

3. Start the router on port 43024.

```
cd internal/liteinterop/router/build
ROUTER_SOAK_SECONDS=1800 ./out/router_tls_fixture 2558fd76-afc7-466e-9613-6b715296a526 \
  00000000-0000-4000-8000-000000000004 00000000-0000-4000-8000-000000000005 \
  hw/root.der hw/router-key.der hw/router-cert.der 43024
```

The arguments are the tenant, router and board IDs from the certificates. Change them if your credentials use other IDs.

4. Flash the board with your computer's IP address. The host router does not answer mDNS.

```
tinygo flash -target xiao-esp32c3 -ldflags="-X main.ssid=SSID -X main.password=PASS -X main.peer=HOST_IP" -monitor ./examples/wendynet-wifi
```

Use the `-target` for your board. The host router serves one board per run, so restart it before switching boards and unplug the others, since they share the same credentials.

The router prints `tls ok`, then `route active`, then a status line every 30 s. It ends with `soak done` and exits nonzero if the route was lost. Open TCP port 43024 if your firewall blocks it.
