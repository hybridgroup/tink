# tink

<p align="center"><img src="images/tink-gopher.png" alt="tink gopher" width="400"></p>

Go and TinyGo packages for joining a Wendy Net mesh.

## Layout

- `pkg/` library packages. Pure Go, testable on the host.
- `examples/` TinyGo programs for ESP32 boards using espradio.
- `cmd/tink/` command line tools built on `pkg/`.

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

## Testing against Lite

`internal/liteinterop` runs tink against wendy-lite's C code built for the host. See its README.md.
