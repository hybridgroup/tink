// Package liteinterop runs tink against wendy-lite's production C code.
// The tests skip unless the fixtures from README.md are built.
package liteinterop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hybridgroup/tink/pkg/meshid"
	"github.com/hybridgroup/tink/pkg/tls13"
	lx509 "github.com/soypat/lcrypto/x509"
)

const (
	tenant = "2558fd76-afc7-466e-9613-6b715296a526"
	lite   = "00000000-0000-4000-8000-000000000004"
	leaf   = "00000000-0000-4000-8000-000000000005"
)

type output struct {
	mu sync.Mutex
	b  strings.Builder
}

func (o *output) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *output) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

type device struct {
	der   []byte
	pkcs8 []byte
}

func issue(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, id string) device {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/device/" + id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: uri.String()},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	return device{der, pkcs8}
}

func TestMeshTLSAgainstLite(t *testing.T) {
	t.Run("accepted", func(t *testing.T) { run(t, leaf, true) })
	// Lite expecting another device must refuse ours, after finish_mesh checks the peer.
	t.Run("wrong peer", func(t *testing.T) { run(t, "00000000-0000-4000-8000-000000000009", false) })
}

func run(t *testing.T, expect string, ok bool) {
	fixture := os.Getenv("LITE_MESH_TLS_FIXTURE")
	if fixture == "" {
		t.Skip("LITE_MESH_TLS_FIXTURE not set")
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tink interop tenant CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	native, ours := issue(t, root, rootKey, lite), issue(t, root, rootKey, leaf)

	// The fixture may run in a container, so files go where it can read them.
	dir := os.Getenv("LITE_MESH_TLS_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	put := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	argv := append(strings.Fields(fixture),
		put("key.der", native.pkcs8), put("certificate.der", native.der), put("trust.der", rootDER),
		"server", port, "0", tenant, lite, expect, "-", "0", "0", "-")
	cmd := exec.Command(argv[0], argv[1:]...)
	var out output
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()

	ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
	raw, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v\n%s", err, out.String())
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(30 * time.Second))

	var cred lx509.Credential
	if err := cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{ours.der}, Key: ours.pkcs8}); err != nil {
		t.Fatal(err)
	}
	var v meshid.Verifier
	err = v.Configure(meshid.Config{
		Roots: lx509.Chain{rootDER}, Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant: tenant, Device: leaf, Peer: lite,
	})
	if err != nil {
		t.Fatal(err)
	}
	var c tls13.Conn
	err = c.Configure(tls13.Config{
		Rand: rand.Reader, Suites: []tls13.Suite{tls13.AES128GCMSHA256()},
		KeyExchanges: []tls13.KeyExchange{tls13.X25519(), tls13.P256()},
		Credential:   &cred, Verifier: &v, ALPN: "wendy-local-mesh-ble/2",
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Open(raw)
	if !ok {
		hs := c.Handshake()
		_, rerr := io.ReadFull(&c, make([]byte, 6))
		if err := <-done; hs == nil && rerr == nil || err == nil {
			t.Fatalf("lite accepted a peer it did not expect\n%s", out.String())
		}
		t.Logf("rejected as expected: handshake=%v read=%v", hs, rerr)
		return
	}
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v\n%s", err, out.String())
	}
	if v.Device() != lite || c.ALPN() != "wendy-local-mesh-ble/2" {
		t.Fatalf("peer %q alpn %q", v.Device(), c.ALPN())
	}
	msg := make([]byte, 6)
	if _, err := io.ReadFull(&c, msg); err != nil {
		t.Fatalf("read: %v\n%s", err, out.String())
	}
	if string(msg) != "hello\x00" {
		t.Fatalf("got %q", msg)
	}
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fixture: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("fixture did not finish\n%s", out.String())
	}
	t.Logf("lite fixture:\n%s", out.String())
}
