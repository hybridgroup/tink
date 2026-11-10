# tink

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
