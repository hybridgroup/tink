package manifest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/hybridgroup/tink/internal/litegolden"
	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/cbor"
	lx509 "github.com/soypat/lcrypto/x509"
)

func liteBody(t *testing.T) Body {
	t.Helper()
	self, err := addr.ParseUUID(litegolden.Self)
	if err != nil {
		t.Fatal(err)
	}
	return Body{
		Device: self, RouterID: 0x0102030405060708, Seqno: 513, Revision: 7,
		Issued: 1700000000000, Expires: 1700000900000,
		AgentPort: 43024, AppPort: 43025, Name: "kitchen", Sensors: true,
	}
}

func encode(t *testing.T, b *Body) []byte {
	t.Helper()
	buf := make([]byte, BodyMax)
	var w cbor.Writer
	w.Reset(buf, 0)
	out, err := b.Write(&w)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestBodyMatchesLite(t *testing.T) {
	b := liteBody(t)
	if got, want := encode(t, &b), litegolden.Get("manifest-body"); !bytes.Equal(got, want) {
		t.Fatalf("body\n got %x\nwant %x", got, want)
	}
	plain := Body{Device: b.Device, RouterID: b.RouterID, Seqno: b.Seqno, Revision: 1,
		Issued: 1700000000000, Expires: 1700000600000, AgentPort: 43024}
	if got, want := encode(t, &plain), litegolden.Get("manifest-body-plain"); !bytes.Equal(got, want) {
		t.Fatalf("plain body\n got %x\nwant %x", got, want)
	}
}

func TestWireMatchesLite(t *testing.T) {
	b := liteBody(t)
	body := encode(t, &b)
	tenant, _ := addr.ParseUUID(litegolden.Tenant)
	principal := addr.Principal(tenant, b.Device)
	sig := make([]byte, 71)
	for i := range sig {
		sig[i] = byte(0x30 + i)
	}
	buf := make([]byte, WireMax)
	var w cbor.Writer
	w.Reset(buf, 0)
	got, err := WriteWire(&w, principal, body, sig)
	if err != nil {
		t.Fatal(err)
	}
	want := litegolden.Get("manifest-wire")
	if !bytes.Equal(got, want) {
		t.Fatalf("wire\n got %x\nwant %x", got, want)
	}
	var d cbor.Doc
	if err := d.Parse(want); err != nil {
		t.Fatal(err)
	}
	var wire Wire
	if err := ReadWire(&d, &wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Body, body) || wire.Principal != principal || !bytes.Equal(wire.Signature, sig) {
		t.Fatal("wire fields")
	}
	var bd cbor.Doc
	if err := bd.Parse(wire.Body); err != nil {
		t.Fatal(err)
	}
	var back Body
	if err := Decode(&bd, &back); err != nil {
		t.Fatal(err)
	}
	if back.Device != b.Device || back.RouterID != b.RouterID || back.Seqno != b.Seqno ||
		back.Revision != b.Revision || back.Issued != b.Issued || back.Expires != b.Expires ||
		back.AgentPort != b.AgentPort || back.Name != b.Name {
		t.Fatalf("decoded %+v", back)
	}
}

// TestDigest builds the preimage as components/wendy_net_peer/tests/manifest_interop_driver.go does.
func TestDigest(t *testing.T) {
	body := litegolden.Get("manifest-body")
	principal := string(litegolden.Get("principal"))
	pre := append([]byte("wendy-local-mesh/manifest/4\x00"), 0, 0, 0, 105)
	pre = append(pre, principal...)
	pre = append(pre, body...)
	want := sha256.Sum256(pre)
	got, err := Digest(principal, body)
	if err != nil || got != want {
		t.Fatalf("digest %x %v", got, err)
	}
}

func TestSignVerify(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "device"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	var cred lx509.Credential
	if err := cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{der}, Key: pkcs8}); err != nil {
		t.Fatal(err)
	}
	b := liteBody(t)
	body := encode(t, &b)
	tenant, _ := addr.ParseUUID(litegolden.Tenant)
	principal := addr.Principal(tenant, b.Device)
	sig := make([]byte, 128)
	n, err := Sign(&cred, principal, body, sig, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig = sig[:n]
	// Go's verifier agrees with the preimage.
	sum, _ := Digest(principal, body)
	if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
		t.Fatal("crypto/ecdsa rejects the signature")
	}
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y) //nolint:staticcheck
	var v Verifier
	if err := v.Verify(pub, principal, body, sig); err != nil {
		t.Fatal(err)
	}
	body[len(body)-1] ^= 1
	if err := v.Verify(pub, principal, body, sig); !errors.Is(err, ErrSignature) {
		t.Fatal("accepted a changed body")
	}
}

func TestBodyRules(t *testing.T) {
	var w cbor.Writer
	buf := make([]byte, BodyMax)
	for _, mut := range []func(*Body){
		func(b *Body) { b.Revision = 0 },
		func(b *Body) { b.RouterID = 0 },
		func(b *Body) { b.Expires = b.Issued + MaxLifetime + 1 },
		func(b *Body) { b.AgentPort = 0 },
	} {
		b := liteBody(t)
		mut(&b)
		w.Reset(buf, 0)
		if _, err := b.Write(&w); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
