package link

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/babel"
	"github.com/hybridgroup/tink/pkg/carrier"
	"github.com/hybridgroup/tink/pkg/cbor"
	"github.com/hybridgroup/tink/pkg/certwire"
	"github.com/hybridgroup/tink/pkg/control"
	"github.com/hybridgroup/tink/pkg/gossip"
	"github.com/hybridgroup/tink/pkg/manifest"
	"github.com/hybridgroup/tink/pkg/packet"
	lx509 "github.com/soypat/lcrypto/x509"
)

var (
	tenant = mustUUID("2558fd76-afc7-466e-9613-6b715296a526")
	leafID = mustUUID("00000000-0000-4000-8000-000000000001")
	rtrID  = mustUUID("00000000-0000-4000-8000-000000000004")
)

func mustUUID(s string) addr.UUID {
	u, err := addr.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func credential(t *testing.T, device addr.UUID) (*lx509.Credential, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse(addr.Principal(tenant, device))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: uri.String()},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	var cred lx509.Credential
	if err := cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{der}, Key: pkcs8, Signers: []lx509.KeySigner{new(lx509.P256Signer)}}); err != nil {
		t.Fatal(err)
	}
	return &cred, key
}

// router plays the Lite side of the session with the same codecs.
type router struct {
	t      *testing.T
	conn   net.Conn
	framer carrier.Framer
	buf    []byte
}

func (r *router) control(b []byte, err error) {
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.framer.WriteControl(r.conn, b); err != nil {
		r.t.Fatal(err)
	}
}

func writer() *cbor.Writer {
	var w cbor.Writer
	w.Reset(make([]byte, control.ControlMax), 0)
	return &w
}

func TestSession(t *testing.T) {
	cred, key := credential(t, leafID)
	leafSide, rtrSide := net.Pipe()
	got := make(chan []byte, 1)
	l, err := New(Config{
		Tenant: tenant, Self: leafID, Peer: rtrID, Credential: cred, RouterID: 0x77,
		NowMS:    func() int64 { return time.Now().UnixMilli() },
		OnPacket: func(p []byte) { got <- append([]byte(nil), p...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	ran := make(chan error, 1)
	go func() { ran <- l.Run(leafSide, stop) }()

	r := &router{t: t, conn: rtrSide, buf: make([]byte, 64<<10)}
	var w cbor.Writer
	w.Reset(make([]byte, 512), 0)
	h, _ := control.WriteHello(&w, rtrID, leafID)
	go carrier.WriteHello(rtrSide, h)
	hb, err := carrier.ReadHello(rtrSide, r.buf)
	if err != nil {
		t.Fatal(err)
	}
	var d cbor.Doc
	if err := d.Parse(hb); err != nil || control.CheckHello(&d, rtrID, leafID) != nil {
		t.Fatal("leaf hello", err)
	}

	// Frames arrive in a goroutine so the router can write while the leaf writes.
	type frame struct {
		control bool
		b       []byte
	}
	frames := make(chan frame, 64)
	go func() {
		for {
			c, p, err := r.framer.ReadFrame(rtrSide, r.buf)
			if err != nil {
				close(frames)
				return
			}
			frames <- frame{c, append([]byte(nil), p...)}
		}
	}()
	var (
		described, wanted bool
		wire              []byte
		fetch             = gossip.Session{Type: 1}
		up                bool
		update            *babel.Message
	)
	emit := func(g *control.Gossip) error {
		r.control(control.WriteGossip(writer(), g))
		return nil
	}
	deadline := time.After(5 * time.Second)
	for wire == nil || update == nil || !up {
		select {
		case <-deadline:
			t.Fatalf("timeout: described=%v manifest=%v update=%v up=%v", described, wire != nil, update != nil, up)
		case f, ok := <-frames:
			if !ok {
				t.Fatal("leaf closed the link")
			}
			if !f.control {
				if f.b[0] != babel.DatagramKind {
					t.Fatalf("datagram kind %d", f.b[0])
				}
				babel.Decode(f.b[1:], func(m *babel.Message) {
					if m.Type == babel.TypeUpdate {
						mm := *m
						update = &mm
					}
					if m.Type == babel.TypeIHU && m.Metric == babel.LANCost {
						up = true
					}
				})
				// Answer with Hello and IHU like Lite's engine.
				var p babel.Packet
				p.Reset()
				p.Hello(1, 400)
				p.IHU(babel.LANCost, 800)
				dg := append([]byte{babel.DatagramKind}, p.Bytes()...)
				r.framer.WriteDatagram(rtrSide, dg)
				continue
			}
			var d cbor.Doc
			if err := d.Parse(f.b); err != nil {
				t.Fatal(err)
			}
			switch control.Kind(&d) {
			case "certificate":
				kind, _, _ := certwire.Parse(&d)
				described = described || kind == "chain"
			case "gossip":
				var g control.Gossip
				if err := control.ReadGossip(&d, &g); err != nil {
					t.Fatal(err)
				}
				if g.Op == control.OpHave && !wanted {
					wanted = true
				}
				fetch.Receive(&g, 0, emit, func(_ uint8, _ [32]byte, data []byte) {
					wire = append([]byte(nil), data...)
				})
			}
		}
	}
	if !described {
		t.Fatal("no chain descriptor before the manifest")
	}

	// Check the manifest as accept_manifest would.
	var md cbor.Doc
	if err := md.Parse(wire); err != nil {
		t.Fatal(err)
	}
	var mw manifest.Wire
	if err := manifest.ReadWire(&md, &mw); err != nil {
		t.Fatal(err)
	}
	if mw.Principal != addr.Principal(tenant, leafID) {
		t.Fatal("principal", mw.Principal)
	}
	pub := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y) //nolint:staticcheck
	var mv manifest.Verifier
	if err := mv.Verify(pub, mw.Principal, mw.Body, mw.Signature); err != nil {
		t.Fatal(err)
	}
	var bd cbor.Doc
	bd.Parse(mw.Body)
	var body manifest.Body
	if err := manifest.Decode(&bd, &body); err != nil {
		t.Fatal(err)
	}
	if body.RouterID != update.Router || body.Seqno != update.Seqno || update.Prefix != leafID.Address() {
		t.Fatalf("route %+v does not match manifest %+v", update, body)
	}

	// IPv6 both ways.
	ip := make([]byte, 1200)
	ip[0], ip[4], ip[5], ip[7] = 0x60, byte((1200-40)>>8), byte((1200-40)&0xff), 64
	ra, la := rtrID.Address(), leafID.Address()
	copy(ip[8:], ra[:])
	copy(ip[24:], la[:])
	var frag [packet.DatagramMax]byte
	for off := 0; off < len(ip); off += packet.FragmentData {
		n, _ := packet.Fragment(&frag, ip, 9, off)
		r.framer.WriteDatagram(rtrSide, frag[:n])
	}
	select {
	case p := <-got:
		if !bytes.Equal(p, ip) {
			t.Fatal("packet differs")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("packet not delivered")
	}
	out := append([]byte(nil), ip...)
	copy(out[8:], la[:])
	copy(out[24:], ra[:])
	sent := make(chan error, 1)
	go func() { sent <- l.Send(out) }()
	var asm packet.Assembler
	for p := []byte(nil); p == nil; {
		f := <-frames
		if f.control || f.b[0] != packet.KindFragment {
			continue
		}
		if p, err = asm.Add(f.b, 0); err != nil {
			t.Fatal(err)
		}
		if p != nil && !bytes.Equal(p, out) {
			t.Fatal("sent packet differs")
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if err := l.Send(ip); err != ErrAdmit {
		t.Fatal("sent a packet with a foreign source", err)
	}
	close(stop)
	if err := <-ran; err != ErrClosed {
		t.Fatal(err)
	}
}
