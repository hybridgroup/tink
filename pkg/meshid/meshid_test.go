package meshid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	lx509 "github.com/soypat/lcrypto/x509"
)

const (
	tenant = "2558fd76-afc7-466e-9613-6b715296a526"
	self   = "00000000-0000-4000-8000-000000000001"
	peer   = "00000000-0000-4000-8000-000000000004"
)

type fixture struct {
	rootDER []byte
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tenant root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	return &fixture{rootDER: der, root: root, rootKey: key}
}

// device issues a leaf like components/wendy_pki/tests/carrier_three_tls_success_driver.go.
func (f *fixture) device(t *testing.T, uris ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var parsed []*url.URL
	for _, u := range uris {
		p, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, p)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: uris[0]},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        parsed, DNSNames: []string{"server"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.root, &key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func principal(tenant, device string) string {
	return "spiffe://wendy.sh/tenant/" + tenant + "/device/" + device
}

func (f *fixture) verifier(t *testing.T, pin string) *Verifier {
	t.Helper()
	v := new(Verifier)
	err := v.Configure(Config{
		Roots:    lx509.Chain{f.rootDER},
		Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant:   tenant, Device: self, Peer: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func signCV(t *testing.T, key *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestVerifyPeer(t *testing.T) {
	f := newFixture(t)
	msg := []byte("certificate verify content")
	for _, tc := range []struct {
		name string
		uris []string
		pin  string
		want error
	}{
		{"device", []string{principal(tenant, peer)}, "", nil},
		{"pinned", []string{principal(tenant, peer)}, peer, nil},
		{"wrong pin", []string{principal(tenant, peer)}, "00000000-0000-4000-8000-000000000009", ErrUnpinned},
		{"self", []string{principal(tenant, self)}, "", ErrSelf},
		{"other tenant", []string{principal("3558fd76-afc7-466e-9613-6b715296a526", peer)}, "", ErrPrincipal},
		{"upper case", []string{principal(tenant, "00000000-0000-4000-8000-00000000000A")}, "", ErrPrincipal},
		{"two devices", []string{principal(tenant, peer), principal(tenant, "00000000-0000-4000-8000-000000000005")}, "", ErrPrincipal},
		{"operator", []string{"spiffe://wendy.sh/tenant/" + tenant + "/operator/" + peer}, "", ErrPrincipal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			der, key := f.device(t, tc.uris...)
			v := f.verifier(t, tc.pin)
			err := v.VerifyPeer(lx509.Chain{der}, lx509.SchemeECDSAP256SHA256, true, nil, msg, signCV(t, key, msg))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if tc.want == nil && v.Device() != peer {
				t.Fatalf("device %q", v.Device())
			} else if tc.want != nil && v.Principal() != "" {
				t.Fatal("principal kept after failure")
			}
		})
	}
}

func TestVerifyPeerBadSignature(t *testing.T) {
	f := newFixture(t)
	der, _ := f.device(t, principal(tenant, peer))
	_, other := f.device(t, principal(tenant, peer))
	msg := []byte("content")
	v := f.verifier(t, "")
	if err := v.VerifyPeer(lx509.Chain{der}, lx509.SchemeECDSAP256SHA256, true, nil, msg, signCV(t, other, msg)); err == nil {
		t.Fatal("accepted a signature by another key")
	}
}

func TestVerifyPeerUntrusted(t *testing.T) {
	f, other := newFixture(t), newFixture(t)
	der, key := other.device(t, principal(tenant, peer))
	msg := []byte("content")
	v := f.verifier(t, "")
	if err := v.VerifyPeer(lx509.Chain{der}, lx509.SchemeECDSAP256SHA256, true, nil, msg, signCV(t, key, msg)); err == nil {
		t.Fatal("accepted a chain from another root")
	}
}
