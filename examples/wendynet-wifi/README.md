# wendynet-wifi

Joins a Wendy Net mesh as a leaf over Wi-Fi. It finds a Lite router with mDNS, or uses `-X main.peer=<ip>`, and dials it on TCP 43024.

Put these DER files in `creds/`. They are not committed.

- `device-cert.der` the device certificate with its `spiffe://wendy.sh/tenant/<t>/device/<d>` URI
- `device-key.der` its P-256 private key, PKCS #8 or SEC 1
- `tenant-root.der` the tenant root CA

The router must be enrolled on the P-256 chain, for example an `esp32c6_net` board, since lcrypto cannot verify ML-DSA yet.

```
tinygo flash -target xiao-esp32s3 -ldflags="-X main.ssid=SSID -X main.password=PASS" -monitor ./examples/wendynet-wifi
```

mDNS sends to 224.0.0.251, which needs lneto to map multicast addresses to their MAC. Until that is released, point a `go.work` at an lneto checkout with the `ipv4-multicast-mac` change, or pass `-X main.peer`.
