package tls13

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	lx509 "github.com/soypat/lcrypto/x509"
	"github.com/soypat/lneto/crypto/tlsraw"
)

type pki struct {
	rootDER   []byte
	rootKey   *ecdsa.PrivateKey
	root      *x509.Certificate
	serverDER []byte
	serverKey *ecdsa.PrivateKey
	clientDER []byte
	clientKey []byte
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	now := time.Now()
	p := &pki{}
	var err error
	p.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	p.rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p.root, _ = x509.ParseCertificate(p.rootDER)
	leaf := func(serial int64, eku x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
			DNSNames: []string{"server"},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	p.serverDER, p.serverKey = leaf(2, x509.ExtKeyUsageServerAuth)
	var ck *ecdsa.PrivateKey
	p.clientDER, ck = leaf(3, x509.ExtKeyUsageClientAuth)
	p.clientKey, err = x509.MarshalPKCS8PrivateKey(ck)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *pki) clientConfig(t *testing.T) Config {
	t.Helper()
	var v lx509.Verifier
	err := v.Configure(lx509.VerifierConfig{
		Algorithms: []lx509.SignatureVerifier{new(lx509.P256Verifier)},
		Roots:      lx509.Chain{p.rootDER},
		Nanotime:   func() int64 { return time.Now().UnixNano() },
	})
	if err != nil {
		t.Fatal(err)
	}
	var cred lx509.Credential
	err = cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{p.clientDER}, Key: p.clientKey, Signers: []lx509.KeySigner{new(lx509.P256Signer)}})
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Rand:         rand.Reader,
		Suites:       []Suite{AES128GCMSHA256()},
		KeyExchanges: []KeyExchange{X25519(), P256()},
		Credential:   &cred,
		Verifier:     &v,
		ServerName:   "server",
		ALPN:         "wendy-local-mesh-ble/2",
	}
}

func (p *pki) serverConfig(curves ...tls.CurveID) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{{Certificate: [][]byte{p.serverDER}, PrivateKey: p.serverKey}},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        pool,
		NextProtos:       []string{"wendy-local-mesh-ble/2"},
		CurvePreferences: curves,
	}
}

// serve runs one TLS server connection that echoes what it reads.
func serve(t *testing.T, cfg *tls.Config) (net.Conn, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		defer ln.Close()
		ss, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		srv := tls.Server(ss, cfg)
		defer srv.Close()
		if err := srv.Handshake(); err != nil {
			done <- err
			return
		}
		if srv.ConnectionState().NegotiatedProtocol != "wendy-local-mesh-ble/2" {
			done <- errors.New("server: wrong ALPN")
			return
		}
		if len(srv.ConnectionState().PeerCertificates) != 1 {
			done <- errors.New("server: no client cert")
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := srv.Read(buf)
			if err == io.EOF {
				done <- nil
				return
			} else if err != nil {
				done <- err
				return
			}
			if _, err := srv.Write(buf[:n]); err != nil {
				done <- err
				return
			}
		}
	}()
	cs, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return cs, done
}

func TestHandshakeMutual(t *testing.T) {
	p := newPKI(t)
	for _, tc := range []struct {
		name  string
		curve tls.CurveID
	}{{"x25519", tls.X25519}, {"p256", tls.CurveP256}} {
		t.Run(tc.name, func(t *testing.T) {
			cs, done := serve(t, p.serverConfig(tc.curve))
			var c Conn
			if err := c.Configure(p.clientConfig(t)); err != nil {
				t.Fatal(err)
			}
			if err := c.Open(cs); err != nil {
				t.Fatal(err)
			}
			if err := c.Handshake(); err != nil {
				t.Fatal("handshake:", err)
			}
			if c.ALPN() != "wendy-local-mesh-ble/2" {
				t.Fatalf("ALPN %q", c.ALPN())
			}
			msg := make([]byte, 20000) // Spans more than one record each way.
			rand.Read(msg)
			// Write while reading the echo so neither side fills its socket buffer.
			wrote := make(chan error, 1)
			go func() {
				_, err := c.Write(msg)
				wrote <- err
			}()
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(&c, got); err != nil {
				t.Fatal(err)
			}
			if err := <-wrote; err != nil {
				t.Fatal(err)
			}
			if string(got) != string(msg) {
				t.Fatal("echo mismatch")
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal("server:", err)
			}
		})
	}
}

func TestHandshakeRejectsWrongRoot(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t)
	cs, done := serve(t, p.serverConfig())
	cfg := p.clientConfig(t)
	cfg.Verifier = other.clientConfig(t).Verifier
	var c Conn
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c.Open(cs)
	var verr verifyError
	if err := c.Handshake(); !errors.As(err, &verr) {
		t.Fatalf("want verify error, got %v", err)
	}
	cs.Close()
	if err := <-done; err == nil {
		t.Fatal("server accepted a failed handshake")
	}
}

func TestHandshakeRejectsWrongALPN(t *testing.T) {
	p := newPKI(t)
	scfg := p.serverConfig()
	scfg.NextProtos = []string{"other/1"}
	cs, done := serve(t, scfg)
	var c Conn
	c.Configure(p.clientConfig(t))
	c.Open(cs)
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake succeeded without ALPN")
	}
	cs.Close()
	<-done
}

func TestMaxRecord(t *testing.T) {
	p := newPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		ss, err := ln.Accept()
		if err != nil {
			return
		}
		scfg := p.serverConfig()
		scfg.DynamicRecordSizingDisabled = true // Send full size records from the start.
		srv := tls.Server(ss, scfg)
		defer srv.Close()
		if srv.Handshake() == nil {
			srv.Write(make([]byte, 8000)) // One record over the client's limit.
			io.Copy(io.Discard, srv)
		}
	}()
	cs, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	cfg := p.clientConfig(t)
	cfg.MaxRecord = 4096
	var c Conn
	if err := c.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	c.Open(cs)
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadFull(&c, make([]byte, 8000))
	if err != alertError(tlsraw.AlertRecordOverflow) {
		t.Fatalf("got %v, want record_overflow", err)
	}
}

func TestErrors(t *testing.T) {
	if alertError(40).Error() != "tls13: sent alert 40" || peerAlertError(42).Error() != "tls13: received alert 42" {
		t.Fatal("alert text")
	}
	v := verifyError{io.EOF}
	if v.Error() != "tls13: peer verification failed: EOF" || !errors.Is(v, io.EOF) {
		t.Fatal("verify error")
	}
}

func TestPeerChain(t *testing.T) {
	p := peerChain{n: 1}
	p.certs[0] = []byte{1, 2, 3}
	if n, err := p.Cert(make([]byte, 2), 0); n != 3 || err != io.ErrShortBuffer {
		t.Fatal("short buffer", n, err)
	}
	if n, err := p.Cert(make([]byte, 3), 0); n != 3 || err != nil {
		t.Fatal("cert", n, err)
	}
	if _, err := p.Cert(nil, 1); err == nil {
		t.Fatal("cert out of range")
	}
	if _, err := p.CertView(1); err == nil {
		t.Fatal("cert view out of range")
	}
}
