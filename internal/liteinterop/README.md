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

## Leaf session

`router/router_fixture.c` puts Lite's router core (`wnr_*`, Babel engine, directory and gossip codec) behind a plain TCP socket. It checks the hello, verifies the leaf certificate with `wendy_pki_mesh_chain`, fetches the manifest by gossip, accepts it with `wnr_manifest`, and reports when `wnr_lookup` authorizes the leaf `/128`. TLS is left out since `TestMeshTLSAgainstLite` covers it.

It needs cJSON, which wendy-lite normally gets from the ESP component manager. From tink, with `L` set to the wendy-lite checkout and after building the TLS fixture above (to reuse its esp-pqc download):

```
B=$PWD/internal/liteinterop/router/build
git clone --depth 1 -b v1.7.19 https://github.com/DaveGamble/cJSON $B/cJSON
docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v $L:$L -v $PWD:$PWD -w $PWD espressif/idf:v6.0.3 bash -c \
  ". \$IDF_PATH/export.sh >/dev/null && cmake -S internal/liteinterop/router -B $B/out -DLITE=$L -DGO_EXECUTABLE=/bin/true \
   -DCJSON_ROOT=$B/cJSON -DFETCHCONTENT_SOURCE_DIR_ESP_PQC=$L/build-pki/_deps/esp_pqc-src && cmake --build $B/out -j8 --target router_fixture"
LITE_ROUTER_FIXTURE=$B/out/router_fixture go test -v -run Session ./internal/liteinterop
```

Build target `router_tls_fixture` as well to put Lite's mesh TLS server in front of the router core. `TestTLSLeafSessionAgainstLite` then runs `pkg/tls13` and `pkg/link` together:

```
LITE_ROUTER_TLS_FIXTURE=$B/out/router_tls_fixture go test -v -run TLSLeaf ./internal/liteinterop
```

The same binary serves a real leaf on the LAN: `router_tls_fixture tenant router leaf root.der key.der cert.der 43024`.
