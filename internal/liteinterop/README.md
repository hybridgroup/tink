# liteinterop

Runs tink against wendy-lite's production C code on the host. The tests skip unless the fixture path is set.

Build the fixture with the ESP-IDF 6.0.3 image, from a wendy-lite checkout:

```
docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v $PWD:$PWD -w $PWD espressif/idf:v6.0.3 bash -c \
  '. $IDF_PATH/export.sh >/dev/null && cmake -S components/wendy_pki/tests -B build-pki -DGO_EXECUTABLE=/bin/true && cmake --build build-pki -j8 --target issuer_interop_success_test'
```

Then run from tink:

```
LITE_MESH_TLS_FIXTURE=<wendy-lite>/build-pki/issuer_interop_success_test go test -v ./internal/liteinterop
```

`TestMeshTLSAgainstLite` makes the fixture a mesh TLS server with ALPN `wendy-local-mesh-ble/2` and connects with `pkg/tls13` and `pkg/meshid`. Lite must accept the expected device and refuse any other.
