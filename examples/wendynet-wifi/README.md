# wendynet-wifi

Joins a Wendy Net mesh as a leaf over Wi-Fi by dialing one Lite router on TCP 43024.

Put these DER files in `creds/`. They are not committed.

- `device-cert.der` the device certificate with its `spiffe://wendy.sh/tenant/<t>/device/<d>` URI
- `device-key.der` its P-256 private key, PKCS #8 or SEC 1
- `tenant-root.der` the tenant root CA

The router must be enrolled on the P-256 chain, for example an `esp32c6_net` board, since lcrypto cannot verify ML-DSA yet.

```
tinygo flash -target xiao-esp32s3 -ldflags="-X main.ssid=SSID -X main.password=PASS -X main.peer=192.168.1.20" -monitor ./examples/wendynet-wifi
```
