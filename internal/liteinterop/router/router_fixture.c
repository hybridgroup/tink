/* A wendy-lite router core behind a TCP socket, for tink's leaf session tests.
 *
 * router_fixture tenant router-uuid leaf-uuid leaf-cert.der root.der
 *   Plain TCP on loopback. The leaf key comes from leaf-cert.der.
 * router_tls_fixture tenant router-uuid leaf-uuid root.der key.der cert.der port
 *   Lite's mesh TLS server on 0.0.0.0:port. The leaf key comes from TLS.
 *
 * Prints the port, then "route active" once wnr_lookup authorizes the leaf /128,
 * and serves 10 s more. */
#include "wendy_net_control.h"
#include "wendy_net_router.h"
#include "wendy_pki_crypto.h"
#include "wendy_pki_mesh.h"
#if ROUTER_TLS
#include "wendy_cert_bundle.h"
#include "wendy_pki_internal.h"
#include "wendy_pki_parsed_identity.h"
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#endif
#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int64_t esp_timer_get_time(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
static int64_t wall_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int fd = -1;
static void die(const char *what, int r)
{
    fprintf(stderr, "router_fixture: %s failed (%d)\n", what, r);
    exit(1);
}
#if ROUTER_TLS
static wendy_pki_connection *tls;
bool wendy_pki_reset_in_progress(void) { return false; }
ssize_t wendy_test_send(int s, const void *data, size_t n, int flags) { return send(s, data, n, flags); }
static ssize_t sock_read(void *ctx, void *data, size_t n)
{
    ssize_t r = recv(*(int *)ctx, data, n, 0);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -2 : r;
}
static ssize_t sock_write(void *ctx, const void *data, size_t n)
{
    ssize_t r = send(*(int *)ctx, data, n, 0);
    return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -3 : r;
}
static void receive_timeout(int s, long seconds)
{
    struct timeval tv = {.tv_sec = seconds};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}
static int sock_wait(void *ctx, bool writing, int64_t deadline)
{
    struct pollfd p = {.fd = *(int *)ctx, .events = writing ? POLLOUT : POLLIN};
    int64_t left = deadline - esp_timer_get_time();
    return left > 0 && poll(&p, 1, (int)(left / 1000) + 1) > 0 ? 0 : -1;
}
static ssize_t do_read(void *p, size_t n) { return wendy_pki_read(tls, p, n); }
static ssize_t do_write(const void *p, size_t n) { return wendy_pki_write(tls, p, n); }
static bool readable(void)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return mbedtls_ssl_get_bytes_avail(&tls->ssl) || poll(&p, 1, 100) > 0;
}
static int read_der(void *context, unsigned index, uint8_t **data, size_t *n)
{
    const mbedtls_x509_crt *p = context;
    while (p && index--)
        p = p->next;
    *data = NULL;
    *n = 0;
    if (!p || !p->raw.len)
        return 0;
    *data = pki_owned_malloc(p->raw.len);
    memcpy(*data, p->raw.p, p->raw.len);
    *n = p->raw.len;
    return 1;
}
#else
static ssize_t do_read(void *p, size_t n) { return read(fd, p, n); }
static ssize_t do_write(const void *p, size_t n) { return write(fd, p, n); }
static bool readable(void)
{
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 100) > 0;
}
#endif
static void full_write(const void *p, size_t n)
{
    while (n) {
        ssize_t w = do_write(p, n);
        if (w <= 0)
            die("write", (int)w);
        p = (const uint8_t *)p + w;
        n -= (size_t)w;
    }
}
static void full_read(void *p, size_t n)
{
    while (n) {
        ssize_t r = do_read(p, n);
        if (r <= 0)
            die("read", (int)r);
        p = (uint8_t *)p + r;
        n -= (size_t)r;
    }
}
static void frame(uint8_t kind, const void *p, size_t n)
{
    uint8_t h[9] = {kind};
    if (kind == 1) {
        wn_put32(h + 1, (uint32_t)(n + 4));
        wn_put32(h + 5, (uint32_t)n);
        full_write(h, 9);
    } else {
        wn_put32(h + 1, (uint32_t)n);
        full_write(h, 5);
    }
    full_write(p, n);
}
static int send_babel(void *ctx, uint64_t link, const void *packet, size_t size)
{
    (void)ctx, (void)link;
    uint8_t d[WN_DATAGRAM_MAX];
    d[0] = 2;
    memcpy(d + 1, packet, size);
    frame(2, d, size + 1);
    return 0;
}
static int publish(void *ctx, const struct wn_origin *o, int64_t unix_ms, int64_t mono)
{
    (void)ctx, (void)o, (void)unix_ms, (void)mono;
    return 0; /* The leaf does not need this router's own manifest. */
}
static uint8_t *load(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die(path, 0);
    fseek(f, 0, SEEK_END);
    *n = (size_t)ftell(f);
    rewind(f);
    uint8_t *p = malloc(*n);
    if (fread(p, 1, *n, f) != *n)
        die(path, 1);
    fclose(f);
    return p;
}
static struct wnr_core core;
static uint8_t body[65536 + 8], artifact[WG_OBJECT_MAX];

int main(int argc, char **argv)
{
#if ROUTER_TLS
    if (argc != 8)
        die("usage", argc);
    signal(SIGPIPE, SIG_IGN);
    if (mbedtls_platform_set_calloc_free(wendy_net_memory_scoped_calloc, wendy_net_memory_scoped_free))
        die("calloc", 0);
#else
    if (argc != 6)
        die("usage", argc);
#endif
    const char *tenant = argv[1], *self = argv[2], *leaf = argv[3];
    if (wendy_pki_crypto_init())
        die("crypto", 0);
#if ROUTER_TLS
    size_t root_n, key_n, own_n;
    uint8_t *root = load(argv[4], &root_n), *key = load(argv[5], &key_n), *own = load(argv[6], &own_n);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)atoi(argv[7]))};
#else
    size_t cert_n, root_n;
    uint8_t *cert = load(argv[4], &cert_n), *root = load(argv[5], &root_n);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
#endif
    int listener = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    socklen_t al = sizeof a;
    if (bind(listener, (struct sockaddr *)&a, sizeof a) || listen(listener, 1) ||
        getsockname(listener, (struct sockaddr *)&a, &al))
        die("listen", 0);
    printf("%u\n", ntohs(a.sin_port));
    fflush(stdout);
#if ROUTER_TLS
    /* Same setup as wendy-lite components/wendy_pki/tests/issuer_interop_success_test.c. */
    wendy_net_memory_t memory = WENDY_NET_MEMORY_INITIALIZER;
    if (!wendy_net_memory_open(&memory, 1024 * 1024, true))
        die("memory", 0);
    (void)wendy_net_memory_scope_enter(&memory, WENDY_NET_MEMORY_EXTERNAL);
    size_t der_n = 0;
    if (wendy_cert_bundle_measure(root, root_n, &der_n))
        die("roots", 0);
    uint8_t *trust_der = calloc(1, der_n + 1);
    if (wendy_cert_bundle_import(root, root_n, trust_der, der_n, &der_n))
        die("roots", 1);
    static mbedtls_x509_crt source;
    mbedtls_x509_crt_init(&source);
    if (pki_parse_certificate_bundle(&source, own, own_n, false))
        die("certificate", 0);
    /* A leaf may abandon a connection mid dial, so serve the next one after a stalled handshake. */
    for (;;) {
        fd = accept(listener, NULL, NULL);
        if (fd < 0)
            die("accept", fd);
        receive_timeout(fd, 1);
        /* pki_tls_net_begin consumes the key and trust copies on every return. */
        uint8_t *k = malloc(key_n), *trust = calloc(1, der_n + 1);
        memcpy(k, key, key_n);
        memcpy(trust, trust_der, der_n);
        struct pki_tls_owned_identity identity = {.key = k, .key_size = key_n, .trust = trust,
                                                  .trust_capacity = der_n + 1, .verify_at = time(NULL),
                                                  .read_der = read_der, .der_context = &source};
        struct wendy_pki_stream stream = {.context = &fd, .read = sock_read, .write = sock_write,
                                          .wait = sock_wait};
        tls = NULL;
        int t = pki_tls_net_begin(&stream, true, tenant, self, &identity,
                                  (struct wendy_conf_span){trust, der_n}, false, &tls);
        int64_t until = esp_timer_get_time() + INT64_C(20000000);
        /* As issuer_interop_success_test: 0 is done, -2/-3 wait, positive is progress. */
        while (!t) {
            t = pki_tls_net_advance(tls, false, leaf);
            if (!t)
                break;
            if (t < 0 && t != -2 && t != -3)
                break;
            if (esp_timer_get_time() > until) {
                t = -9;
                break;
            }
            if (t == -2 || t == -3)
                sock_wait(&fd, t == -3, esp_timer_get_time() + 1000000);
            t = 0;
        }
        if (!t)
            break;
        fprintf(stderr, "handshake failed (%d), waiting for the next connection\n", t);
        if (tls)
            wendy_pki_close(tls);
        close(fd);
    }
    receive_timeout(fd, 0);
    printf("tls ok alpn=%s\n", mbedtls_ssl_get_alpn_protocol(&tls->ssl));
    fflush(stdout);
#else
    fd = accept(listener, NULL, NULL);
    if (fd < 0)
        die("accept", fd);
#endif

    /* Hello preamble both ways, as peer.c setup_hello does. */
    uint8_t len[4];
    full_read(len, 4);
    uint32_t n = wn_get32(len);
    if (!n || n > WN_CONTROL_MAX)
        die("hello size", (int)n);
    full_read(body, n);
    if (wn_router_hello_check(body, n, self, leaf))
        die("hello check", 0);
    char hello[WN_CONTROL_MAX];
    int hn = wn_router_hello_write(self, leaf, hello + 4, sizeof hello - 4);
    if (hn < 0)
        die("hello write", hn);
    wn_put32((uint8_t *)hello, (uint32_t)hn);
    full_write(hello, (size_t)hn + 4);
    printf("hello ok\n");
    fflush(stdout);

    struct wnr_config cfg = {.tenant = tenant, .device = self, .router = 0x0102030405060708,
                             .seed = 7, .publish = publish, .send = send_babel};
    memset(cfg.trust_hash, 42, 32);
    int r;
    if ((r = wnr_init(&core, &cfg, esp_timer_get_time(), NULL, 0)))
        die("wnr_init", r);
    if ((r = wnr_start(&core, wall_ms(), esp_timer_get_time())))
        die("wnr_start", r);
    /* The leaf key comes from its TLS certificate, install_peer_identity in peer.c. */
    struct wendy_pki_mesh_peer peer;
#if ROUTER_TLS
    if ((r = wendy_pki_mesh_authenticated_peer(tls, &peer)))
        die("wendy_pki_mesh_authenticated_peer", r);
#else
    const uint8_t *der[1] = {cert};
    if ((r = wendy_pki_mesh_chain(der, &cert_n, 1, root, root_n, tenant, time(NULL), &peer)))
        die("wendy_pki_mesh_chain", r);
#endif
    if ((r = wnr_identity(&core, &peer, wall_ms(), esp_timer_get_time())))
        die("wnr_identity", r);
    uint64_t link;
    if ((r = wnr_attach(&core, leaf, WNR_LAN_COST, wall_ms(), esp_timer_get_time(), &link)))
        die("wnr_attach", r);

    uint8_t leaf_uuid[16], leaf_address[16];
    wn_uuid_parse(leaf, leaf_uuid);
    wn_address(leaf_uuid, leaf_address);
    size_t have = 0;
    bool fetching = false, accepted = false, active = false;
    int64_t deadline = esp_timer_get_time() + INT64_C(45000000);
    while (esp_timer_get_time() < deadline) {
        if (readable()) {
            uint8_t h[5];
            full_read(h, 5);
            uint32_t size = wn_get32(h + 1);
            if (size > sizeof body)
                die("frame size", (int)size);
            full_read(body, size);
            if (h[0] == 2 && size && body[0] == 2) {
                r = wnr_receive(&core, link, body + 1, size - 1, wall_ms(), esp_timer_get_time());
                if (r < 0)
                    fprintf(stderr, "babel receive %d\n", r);
            } else if (h[0] == 1) {
                if (size < 4 || wn_get32(body) != size - 4)
                    die("control framing", 0);
                const uint8_t *c = body + 4;
                size_t cn = size - 4;
                struct wn_doc d;
                if (wn_doc_parse_bounded(&d, c, cn, 65536))
                    die("control cbor", 0);
                if (wn_doc_equal(&d, wn_doc_member(&d, 0, "kind"), "certificate")) {
                    printf("certificate message\n");
                } else if (wn_doc_equal(&d, wn_doc_member(&d, 0, "kind"), "gossip")) {
                    struct wg_message m;
                    if (wn_gossip_read_view(c, cn, &m))
                        die("gossip read", 0);
                    char out[WN_CONTROL_MAX];
                    if (m.op == WG_HAVE && !fetching && !accepted) {
                        struct wg_message want = {.id = m.id, .op = WG_WANT, .request = 1};
                        int wn = wn_gossip_write(&want, out, sizeof out);
                        frame(1, out, (size_t)wn);
                        fetching = true;
                        have = 0;
                    } else if (m.op == WG_DATA && fetching && m.request == 1) {
                        if (m.offset != have || m.total > sizeof artifact)
                            die("gossip offset", (int)m.offset);
                        memcpy(artifact + have, m.data, m.size);
                        have += m.size;
                        if (have == m.total) {
                            uint8_t digest[32];
                            fetching = false;
                            r = wn_gossip_identify(NULL, 1, artifact, have, digest);
                            if (r || memcmp(digest, m.id.hash, 32))
                                die("gossip digest", r);
                            r = wnr_manifest(&core, artifact, have, wall_ms(), esp_timer_get_time());
                            printf("manifest accept result %d\n", r);
                            fflush(stdout);
                            if (r)
                                die("wnr_manifest", r);
                            accepted = true;
                        }
                    }
                } else {
                    printf("control %.*s\n", (int)cn > 40 ? 40 : (int)cn, "");
                }
            }
        }
        if ((r = wnr_tick(&core, wall_ms(), esp_timer_get_time())) < 0)
            die("wnr_tick", r);
        struct wb_route route;
        if (!active && wnr_lookup(&core, leaf_address, esp_timer_get_time(), &route)) {
            printf("route active router=%016llx seqno=%u metric=%u\n",
                   (unsigned long long)route.router, route.seqno, route.metric);
            fflush(stdout);
            /* Keep serving so the leaf also sees the link up. */
            active = true;
            deadline = esp_timer_get_time() + INT64_C(10000000);
        }
    }
    if (!active)
        die("route never became active", accepted);
    return 0;
}
