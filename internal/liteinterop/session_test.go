package liteinterop

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/link"
	"github.com/hybridgroup/tink/pkg/meshid"
	"github.com/hybridgroup/tink/pkg/tls13"
	lx509 "github.com/soypat/lcrypto/x509"
)

// TestLeafSessionAgainstLite runs pkg/link against Lite's router core.
// It passes once Lite's wnr_lookup authorizes the leaf /128.
func TestLeafSessionAgainstLite(t *testing.T) {
	fixture := os.Getenv("LITE_ROUTER_FIXTURE")
	if fixture == "" {
		t.Skip("LITE_ROUTER_FIXTURE not set")
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
	ours := issue(t, root, rootKey, leaf)
	dir := t.TempDir()
	certPath, rootPath := filepath.Join(dir, "leaf.der"), filepath.Join(dir, "root.der")
	os.WriteFile(certPath, ours.der, 0644)
	os.WriteFile(rootPath, rootDER, 0644)

	cmd := exec.Command(fixture, tenant, lite, leaf, certPath, rootPath)
	stdout, _ := cmd.StdoutPipe()
	var stderr output
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() {
		t.Fatalf("no port\n%s", stderr.String())
	}
	conn, err := net.Dial("tcp", "127.0.0.1:"+strings.TrimSpace(lines.Text()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var cred lx509.Credential
	if err := cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{ours.der}, Key: ours.pkcs8, Signers: []lx509.KeySigner{new(lx509.P256Signer)}}); err != nil {
		t.Fatal(err)
	}
	tn, _ := addr.ParseUUID(tenant)
	self, _ := addr.ParseUUID(leaf)
	peer, _ := addr.ParseUUID(lite)
	l, err := link.New(link.Config{
		Tenant: tn, Self: self, Peer: peer, Credential: &cred, RouterID: 0x8000000000000005,
		NowMS: func() int64 { return time.Now().UnixMilli() },
		Log:   func(m string) { t.Log("leaf:", m) },
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go l.Run(conn, stop)

	active := make(chan struct{})
	go func() {
		for lines.Scan() {
			line := lines.Text()
			t.Log("lite:", line)
			if strings.HasPrefix(line, "route active") {
				close(active)
			}
		}
	}()
	select {
	case <-active:
	case <-time.After(60 * time.Second):
		t.Fatalf("lite did not authorize the leaf route\n%s", stderr.String())
	}
	for start := time.Now(); !l.Up(); time.Sleep(100 * time.Millisecond) {
		if time.Since(start) > 9*time.Second {
			t.Fatal("leaf does not see the Babel link up")
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("fixture: %v\n%s", err, stderr.String())
	}
}

// TestTLSLeafSessionAgainstLite runs tls13 and the leaf session together
// against Lite's mesh TLS server and router core in router_tls_fixture.
func TestTLSLeafSessionAgainstLite(t *testing.T) {
	fixture := os.Getenv("LITE_ROUTER_TLS_FIXTURE")
	if fixture == "" {
		t.Skip("LITE_ROUTER_TLS_FIXTURE not set")
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tink interop tenant CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	native, ours := issue(t, root, rootKey, lite), issue(t, root, rootKey, leaf)
	dir := t.TempDir()
	put := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0600)
		return p
	}
	cmd := exec.Command(fixture, tenant, lite, leaf, put("root.der", rootDER), put("key.der", native.pkcs8),
		put("cert.der", native.der), "0")
	stdout, _ := cmd.StdoutPipe()
	var stderr output
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() {
		t.Fatalf("no port\n%s", stderr.String())
	}
	raw, err := net.Dial("tcp", "127.0.0.1:"+strings.TrimSpace(lines.Text()))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	var cred lx509.Credential
	cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{ours.der}, Key: ours.pkcs8, Signers: []lx509.KeySigner{new(lx509.P256Signer)}})
	var v meshid.Verifier
	v.Configure(meshid.Config{Roots: lx509.Chain{rootDER}, Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant: tenant, Device: leaf, Peer: lite})
	var c tls13.Conn
	c.Configure(tls13.Config{Rand: rand.Reader, Suites: []tls13.Suite{tls13.AES128GCMSHA256()},
		KeyExchanges: []tls13.KeyExchange{tls13.X25519(), tls13.P256()},
		Credential:   &cred, Verifier: &v, ALPN: "wendy-local-mesh-ble/2", MaxRecord: 4096})
	c.Open(raw)
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake: %v\n%s", err, stderr.String())
	}
	tn, _ := addr.ParseUUID(tenant)
	self, _ := addr.ParseUUID(leaf)
	peer, _ := addr.ParseUUID(v.Device())
	l, err := link.New(link.Config{Tenant: tn, Self: self, Peer: peer, Credential: &cred,
		RouterID: 0x8000000000000005, NowMS: func() int64 { return time.Now().UnixMilli() },
		Log: func(m string) { t.Log("leaf:", m) }})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go l.Run(&c, stop)
	active := make(chan struct{})
	go func() {
		for lines.Scan() {
			t.Log("lite:", lines.Text())
			if strings.HasPrefix(lines.Text(), "route active") {
				close(active)
			}
		}
	}()
	select {
	case <-active:
	case <-time.After(60 * time.Second):
		t.Fatalf("lite did not authorize the leaf route\n%s", stderr.String())
	}
	for start := time.Now(); !l.Up(); time.Sleep(100 * time.Millisecond) {
		if time.Since(start) > 9*time.Second {
			t.Fatal("leaf does not see the Babel link up")
		}
	}
}
