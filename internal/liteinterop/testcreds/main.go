// Command testcreds creates a test tenant root with router and board credentials for the host router.
// Usage: go run ./internal/liteinterop/testcreds <router-dir> <board-creds-dir>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	tenant = "2558fd76-afc7-466e-9613-6b715296a526"
	router = "00000000-0000-4000-8000-000000000004"
	board  = "00000000-0000-4000-8000-000000000005"
	valid  = 30 * 24 * time.Hour
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: testcreds <router-dir> <board-creds-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "testcreds:", err)
		os.Exit(1)
	}
}

func run(routerDir, boardDir string) error {
	out := []string{
		filepath.Join(routerDir, "root.der"), filepath.Join(routerDir, "router-cert.der"), filepath.Join(routerDir, "router-key.der"),
		filepath.Join(boardDir, "tenant-root.der"), filepath.Join(boardDir, "device-cert.der"), filepath.Join(boardDir, "device-key.der"),
	}
	for _, p := range out {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists, remove it first", p)
		}
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tink hardware test tenant"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(valid), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	issue := func(serial int64, device string) (cert, key []byte, err error) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		u, err := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/device/" + device)
		if err != nil {
			return nil, nil, err
		}
		c := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: u.String()},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(valid),
			KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{u},
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if cert, err = x509.CreateCertificate(rand.Reader, c, root, &k.PublicKey, rootKey); err != nil {
			return nil, nil, err
		}
		key, err = x509.MarshalPKCS8PrivateKey(k)
		return cert, key, err
	}
	routerCert, routerKey, err := issue(2, router)
	if err != nil {
		return err
	}
	boardCert, boardKey, err := issue(3, board)
	if err != nil {
		return err
	}
	data := [][]byte{rootDER, routerCert, routerKey, rootDER, boardCert, boardKey}
	for _, dir := range []string{routerDir, boardDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	for i, p := range out {
		if err := os.WriteFile(p, data[i], 0600); err != nil {
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}
