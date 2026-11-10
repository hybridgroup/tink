/* Prints golden vectors from the wendy-lite wire code as "name hex" lines. */
#include "psa/crypto.h"
#include "wendy_net_control.h"
#include "certificate_wire.h"
#include "wendy_babel.h"
#include "wendy_net_peer_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

psa_status_t psa_hash_setup(psa_hash_operation_t *o, int a) { (void)o, (void)a; return -1; }
psa_status_t psa_hash_update(psa_hash_operation_t *o, const uint8_t *d, size_t n) { (void)o, (void)d, (void)n; return -1; }
psa_status_t psa_hash_finish(psa_hash_operation_t *o, uint8_t *h, size_t n, size_t *w) { (void)o, (void)h, (void)n, (void)w; return -1; }
psa_status_t psa_hash_abort(psa_hash_operation_t *o) { (void)o; return 0; }
int wendy_pki_crypto_init(void) { return -1; }
void *wendy_net_malloc(size_t n) { return malloc(n); }
void *wendy_net_calloc(size_t n, size_t s) { return calloc(n, s); }
void wendy_net_free(void *p) { free(p); }

static void out(const char *name, const void *data, int n)
{
    if (n <= 0) {
        fprintf(stderr, "%s: failed\n", name);
        exit(1);
    }
    printf("%s ", name);
    for (int i = 0; i < n; i++)
        printf("%02x", ((const uint8_t *)data)[i]);
    printf("\n");
}

#define TENANT "2558fd76-afc7-466e-9613-6b715296a526"
#define SELF "00000000-0000-4000-8000-000000000001"
#define PEER "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

int main(void)
{
    static uint8_t buf[65536];
    char principal[106];
    int n;

    n = wn_router_hello_write(SELF, PEER, (char *)buf, sizeof buf);
    out("hello", buf, n);

    wn_principal(TENANT, PEER, principal);
    out("principal", principal, (int)strlen(principal));
    out("identity-request", buf, wn_identity_request_write(principal, (char *)buf, sizeof buf));
    out("manifest-request", buf, wn_manifest_request_write(principal, (char *)buf, sizeof buf));
    out("manifest-missing", buf, wn_directory_missing_write(principal, true, (char *)buf, sizeof buf));
    out("identity-missing", buf, wn_directory_missing_write(principal, false, (char *)buf, sizeof buf));

    uint8_t uuid[16], address[16];
    char prefix[48];
    wn_uuid_parse(PEER, uuid);
    wn_address(uuid, address);
    out("address", address, 16);
    wn_prefix(uuid, prefix);
    out("prefix", prefix, (int)strlen(prefix));

    static uint8_t chunk[WG_CHUNK];
    for (unsigned i = 0; i < sizeof chunk; i++)
        chunk[i] = (uint8_t)(i * 7 + 3);
    struct wg_message m = {.id.type = 1, .op = WG_HAVE};
    for (unsigned i = 0; i < 32; i++)
        m.id.hash[i] = (uint8_t)(0xa0 + i);
    out("gossip-have", buf, wn_gossip_write(&m, (char *)buf, sizeof buf));
    m.op = WG_WANT;
    m.request = 0x1234567890;
    out("gossip-want", buf, wn_gossip_write(&m, (char *)buf, sizeof buf));
    m.op = WG_DATA;
    m.offset = 1024;
    m.total = 1500;
    m.data = chunk;
    m.size = 476;
    out("gossip-data", buf, wn_gossip_write(&m, (char *)buf, sizeof buf));

    uint8_t self[16];
    wn_uuid_parse(SELF, self);
    struct wn_origin origin = {.router_id = 0x0102030405060708, .seqno = 513};
    n = wn_manifest_capabilities_write(self, &origin, 7, 1700000000000, 1700000900000, 43024,
                                       43025, "kitchen", true, (char *)buf, sizeof buf);
    out("manifest-body", buf, n);
    static uint8_t body[WN_MANIFEST_BODY_MAX];
    memcpy(body, buf, (size_t)n);
    uint8_t signature[71];
    for (unsigned i = 0; i < sizeof signature; i++)
        signature[i] = (uint8_t)(0x30 + i);
    char self_principal[106];
    wn_principal(TENANT, SELF, self_principal);
    out("manifest-wire", buf, wn_manifest_wire_write(self_principal, body, (size_t)n, signature,
                                                     sizeof signature, (char *)buf, sizeof buf));
    n = wn_manifest_write(self, &origin, 1, 1700000000000, 1700000600000, 43024, (char *)buf,
                          sizeof buf);
    out("manifest-body-plain", buf, n);

    uint8_t packet[1320] = {0x60};
    packet[4] = (1320 - 40) >> 8;
    packet[5] = (1320 - 40) & 0xff;
    for (unsigned i = 8; i < sizeof packet; i++)
        packet[i] = (uint8_t)(i * 13);
    uint8_t frag[WN_DATAGRAM_MAX];
    out("fragment-0", frag, (int)wn_fragment(frag, packet, sizeof packet, 0xdeadbeef, 0));
    out("fragment-1", frag, (int)wn_fragment(frag, packet, sizeof packet, 0xdeadbeef, 1091));

    struct wncf_chain chain = {.count = 2};
    memcpy(chain.principal, principal, 106);
    for (unsigned i = 0; i < 32; i++) {
        chain.hashes[0][i] = (uint8_t)i;
        chain.hashes[1][i] = (uint8_t)(0x80 + i);
    }
    out("cert-chain", buf, wncf_chain_write(&chain, (char *)buf, sizeof buf));
    struct wncf_request request = {.offset = 1024};
    memcpy(request.hash, chain.hashes[1], 32);
    out("cert-request", buf, wncf_request_write(&request, (char *)buf, sizeof buf));
    out("cert-missing", buf, wncf_missing_write(&request, (char *)buf, sizeof buf));
    struct wncf_chunk piece = {.offset = 1024, .total = 1100, .size = 76};
    memcpy(piece.hash, chain.hashes[1], 32);
    out("cert-chunk", buf, wncf_chunk_write(&piece, chunk, (char *)buf, sizeof buf));

    struct wb_message hello = {.type = WB_HELLO, .seqno = 0x1234, .interval = 400};
    out("babel-hello", buf, (int)wb_encode(&hello, buf, sizeof buf));
    hello.unicast = true;
    out("babel-hello-unicast", buf, (int)wb_encode(&hello, buf, sizeof buf));
    struct wb_message ihu = {.type = WB_IHU, .metric = 96, .interval = 800};
    out("babel-ihu", buf, (int)wb_encode(&ihu, buf, sizeof buf));
    struct wb_message update = {.type = WB_UPDATE, .interval = 1600, .seqno = 513, .metric = 0,
                                .router = 0x0102030405060708};
    wn_address(uuid, update.prefix.bytes);
    update.prefix.bits = 128;
    update.prefix.family = 6;
    out("babel-update", buf, (int)wb_encode(&update, buf, sizeof buf));
    struct wb_message retract = update;
    retract.metric = WB_INFINITY;
    out("babel-retract", buf, (int)wb_encode(&retract, buf, sizeof buf));
    struct wb_message wildcard = {.type = WB_REQUEST, .wildcard = true};
    out("babel-request-wildcard", buf, (int)wb_encode(&wildcard, buf, sizeof buf));
    struct wb_message seqreq = {.type = WB_SEQ_REQUEST, .prefix = update.prefix, .seqno = 514,
                                .hops = 16, .router = 0x0102030405060708};
    out("babel-seqrequest", buf, (int)wb_encode(&seqreq, buf, sizeof buf));
    struct wb_message ack = {.type = WB_ACK, .opaque = 0xbeef};
    out("babel-ack", buf, (int)wb_encode(&ack, buf, sizeof buf));
    struct wb_message ackreq = {.type = WB_ACK_REQUEST, .opaque = 0xbeef, .interval = 200};
    out("babel-ackrequest", buf, (int)wb_encode(&ackreq, buf, sizeof buf));
    return 0;
}
