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
	lx509 "github.com/soypat/lcrypto/x509"
)

// TestLeafSessionAgainstLite runs pkg/link against Lite's router core.
// router_fixture verifies our certificate with wendy_pki_mesh_chain, fetches
// the manifest by gossip, accepts it with wnr_manifest and passes once
// wnr_lookup authorizes the leaf /128 from our Babel route.
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
	if err := cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{ours.der}, Key: ours.pkcs8}); err != nil {
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
