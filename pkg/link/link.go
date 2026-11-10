// Package link runs a Wendy Net leaf session over one authenticated stream
// to its router, following the session in wendy-lite
// components/wendy_net_peer/src/peer.c and router_session.c:
//
//  1. Both sides send the hello preamble and check the other's.
//  2. The leaf describes its certificate chain and announces its signed
//     manifest with gossip HAVE. The router fetches it with WANT.
//  3. Babel Hello, IHU and Update keep the link and the leaf /128 route up.
//     The route is accepted once its routerId and seqno match the manifest.
//  4. IPv6 packets travel as fragment datagrams.
package link

import (
	"errors"
	"io"
	"sync"
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
	"github.com/soypat/lcrypto"
	lx509 "github.com/soypat/lcrypto/x509"
)

const (
	// RepublishMS matches the 300 s republish of router.c.
	RepublishMS = 300000
	// Lifetime is the manifest lease, the largest Lite accepts.
	Lifetime = manifest.MaxLifetime
	tick     = 250 * time.Millisecond
)

var (
	ErrConfig = errors.New("link: invalid config")
	ErrClosed = errors.New("link: closed")
	ErrAdmit  = errors.New("link: packet is not from this device")
)

// Config configures a leaf session.
type Config struct {
	Tenant, Self addr.UUID
	// Peer is the router device UUID verified by TLS, see meshid.Verifier.Device.
	Peer addr.UUID
	// Credential is the device key and chain. It signs the manifest.
	Credential lcrypto.Credential
	// RouterID is announced in Babel and the manifest. Use a stable non zero value.
	RouterID uint64
	// AgentPort is the management port in the manifest, 43024 if zero.
	AgentPort uint16
	Name      string
	// NowMS returns Unix milliseconds from a real clock, such as NTP.
	NowMS func() int64
	// OnPacket receives IPv6 packets addressed to this device. It must not keep p.
	OnPacket func(p []byte)
	// Log receives short diagnostics when set.
	Log func(msg string)
}

// Link is one leaf session. Create it with New and run it with Run.
type Link struct {
	cfg       Config
	principal string
	notBefore int64
	notAfter  int64
	rw        io.ReadWriter

	mu        sync.Mutex // Serializes writes and session state.
	framer    carrier.Framer
	speaker   babel.Speaker
	gossip    gossip.Session
	chain     certwire.Chain
	out       [control.ControlMax]byte
	mbody     [manifest.BodyMax]byte
	mwire     [manifest.WireMax]byte
	sig       [manifest.SignatureMax]byte
	digest    [32]byte
	published bool
	revision  uint64
	nextPub   int64
	frag      [packet.DatagramMax]byte
	fragID    uint32
	pkt       babel.Packet
	dgram     [1 + babel.PacketMax]byte

	// Reader side.
	in    []byte
	doc   cbor.Doc
	asm   packet.Assembler
	start time.Time
}

// New checks cfg.
func New(cfg Config) (*Link, error) {
	if cfg.Credential == nil || cfg.NowMS == nil || cfg.RouterID == 0 || cfg.RouterID == ^uint64(0) ||
		cfg.Self == cfg.Peer {
		return nil, ErrConfig
	}
	if cfg.AgentPort == 0 {
		cfg.AgentPort = 43024
	}
	l := &Link{cfg: cfg, principal: addr.Principal(cfg.Tenant, cfg.Self)}
	der, err := cfg.Credential.CertView(0)
	if err != nil {
		return nil, err
	}
	var leaf lx509.Certificate
	if err := leaf.Parse(der); err != nil {
		return nil, err
	}
	l.notBefore, l.notAfter = leaf.NotBefore*1000, leaf.NotAfter*1000
	if err := l.chain.Configure(l.principal, cfg.Credential); err != nil {
		return nil, err
	}
	l.gossip.Type = control.TypeManifest
	l.speaker = babel.Speaker{Router: cfg.RouterID, Prefix: cfg.Self.Address(), Seqno: 1}
	l.in = make([]byte, carrier.MaxFrameBuffer)
	return l, nil
}

func (l *Link) logf(msg string) {
	if l.cfg.Log != nil {
		l.cfg.Log(msg)
	}
}

// Run exchanges the hello on rw and serves the session until rw fails or
// stop is closed. rw is the TLS connection to cfg.Peer.
func (l *Link) Run(rw io.ReadWriter, stop <-chan struct{}) error {
	l.rw = rw
	l.start = time.Now()
	if err := l.hello(); err != nil {
		return err
	}
	l.logf("hello ok")
	l.mu.Lock()
	err := l.publish()
	l.mu.Unlock()
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- l.readLoop() }()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-stop:
			return ErrClosed
		case <-t.C:
			if err := l.poll(); err != nil {
				return err
			}
		}
	}
}

// Up reports whether Babel sees the router and the router sees us.
func (l *Link) Up() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.speaker.Up(l.mono())
}

// mono is milliseconds since Run, for Babel and gossip timers.
func (l *Link) mono() int64 { return time.Since(l.start).Milliseconds() }

func (l *Link) hello() error {
	var w cbor.Writer
	w.Reset(l.out[:], 0)
	h, err := control.WriteHello(&w, l.cfg.Self, l.cfg.Peer)
	if err != nil {
		return err
	}
	if err := carrier.WriteHello(l.rw, h); err != nil {
		return err
	}
	b, err := carrier.ReadHello(l.rw, l.in)
	if err != nil {
		return err
	}
	if err := l.doc.Parse(b); err != nil {
		return err
	}
	return control.CheckHello(&l.doc, l.cfg.Self, l.cfg.Peer)
}

func (l *Link) writer() *cbor.Writer {
	var w cbor.Writer
	w.Reset(l.out[:], control.ControlMax)
	return &w
}

func (l *Link) sendControl(b []byte, err error) error {
	if err != nil {
		return err
	}
	return l.framer.WriteControl(l.rw, b)
}

func (l *Link) emit(g *control.Gossip) error {
	return l.sendControl(control.WriteGossip(l.writer(), g))
}

// publish signs a manifest for the current seqno and announces it. Call with mu held.
func (l *Link) publish() error {
	now := l.cfg.NowMS()
	expires := min(now+Lifetime, l.notAfter)
	if now < l.notBefore || expires <= now {
		return errors.New("link: clock outside the certificate validity")
	}
	// Wall clock revisions only grow across restarts, which Lite requires.
	l.revision = max(l.revision+1, uint64(now))
	body := manifest.Body{
		Device: l.cfg.Self, RouterID: l.cfg.RouterID, Seqno: l.speaker.Seqno, Revision: l.revision,
		Issued: now, Expires: expires, AgentPort: l.cfg.AgentPort, Name: l.cfg.Name,
	}
	var w cbor.Writer
	w.Reset(l.mbody[:], 0)
	b, err := body.Write(&w)
	if err != nil {
		return err
	}
	n, err := manifest.Sign(l.cfg.Credential, l.principal, b, l.sig[:])
	if err != nil {
		return err
	}
	w.Reset(l.mwire[:], 0)
	wire, err := manifest.WriteWire(&w, l.principal, b, l.sig[:n])
	if err != nil {
		return err
	}
	if l.published {
		l.gossip.Forget(l.digest)
	}
	l.digest = l.gossip.Offer(wire, uint64(l.mono()+Lifetime))
	l.published = true
	l.nextPub = l.mono() + RepublishMS
	// Lite describes the artifact's chain before serving it, router_session.c emit.
	if err := l.sendControl(l.chain.WriteDescriptor(l.writer())); err != nil {
		return err
	}
	l.logf("manifest published")
	return l.gossip.Have(l.emit, l.digest)
}

func (l *Link) poll() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.mono()
	if l.speaker.SeqnoWanted {
		l.speaker.SeqnoWanted = false
		l.speaker.Seqno++
		if err := l.publish(); err != nil {
			return err
		}
		l.speaker.Announce()
	} else if now >= l.nextPub {
		if err := l.publish(); err != nil {
			return err
		}
	}
	l.speaker.Poll(&l.pkt, now)
	if !l.pkt.Empty() {
		if err := l.sendBabel(); err != nil {
			return err
		}
	}
	// One DATA chunk per tick keeps Babel timely, as wg_poll does.
	for range 4 {
		if err := l.gossip.Poll(uint64(now), l.emit); err != nil {
			return err
		}
		if !l.gossip.Busy() {
			break
		}
	}
	return nil
}

func (l *Link) sendBabel() error {
	l.dgram[0] = babel.DatagramKind
	n := 1 + copy(l.dgram[1:], l.pkt.Bytes())
	return l.framer.WriteDatagram(l.rw, l.dgram[:n])
}

// Send sends an IPv6 packet from this device into the mesh.
func (l *Link) Send(p []byte) error {
	self := l.cfg.Self.Address()
	if len(p) < 40 || string(p[8:24]) != string(self[:]) || !meshAddress(p[24:40]) {
		return ErrAdmit
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fragID++
	for off := 0; off < len(p); off += packet.FragmentData {
		n, err := packet.Fragment(&l.frag, p, l.fragID, off)
		if err != nil {
			return err
		}
		if err := l.framer.WriteDatagram(l.rw, l.frag[:n]); err != nil {
			return err
		}
	}
	return nil
}

// meshAddress matches the device and operator ULAs, as wn_ip_admits does.
func meshAddress(a []byte) bool {
	return a[0] == 0xfd && a[1] == 0x45 && a[2] == 0xb8 && a[3] == 0x91 && a[4] == 0x56 &&
		(a[5] == 0x7f || a[5] == 0x80)
}

func (l *Link) readLoop() error {
	var rf carrier.Framer
	for {
		isControl, payload, err := rf.ReadFrame(l.rw, l.in)
		if err != nil {
			return err
		}
		if isControl {
			err = l.handleControl(payload)
		} else {
			err = l.handleDatagram(payload)
		}
		if err != nil {
			return err
		}
	}
}

func (l *Link) handleDatagram(d []byte) error {
	switch d[0] {
	case babel.DatagramKind:
		l.mu.Lock()
		err := l.speaker.Receive(d[1:], l.mono())
		l.mu.Unlock()
		if err != nil {
			l.logf("babel: " + err.Error())
		}
		return nil // Lite only counts malformed Babel.
	case packet.KindFragment:
		p, err := l.asm.Add(d, l.mono()*1000)
		if err != nil {
			return err // Lite closes the link on a bad fragment.
		}
		self := l.cfg.Self.Address()
		if p != nil && string(p[24:40]) == string(self[:]) && meshAddress(p[8:24]) && l.cfg.OnPacket != nil {
			l.cfg.OnPacket(p)
		}
	}
	return nil
}

func (l *Link) handleControl(b []byte) error {
	d := &l.doc
	if err := d.Parse(b); err != nil {
		return err // Lite closes the link on invalid control CBOR.
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch control.Kind(d) {
	case "gossip":
		var g control.Gossip
		switch err := control.ReadGossip(d, &g); err {
		case nil:
		case control.ErrUnsupported:
			return nil
		default:
			return err
		}
		// A leaf serves its own manifest and does not fetch others.
		if g.Op == control.OpHave {
			return nil
		}
		return l.gossip.Receive(&g, uint64(l.mono()), l.emit, nil)
	case "certificate":
		kind, obj, err := certwire.Parse(d)
		if err != nil || kind != "request" {
			return nil
		}
		q, err := certwire.ReadRequest(d, obj)
		if err != nil {
			return nil
		}
		return l.sendControl(l.chain.Answer(l.writer(), q))
	case "manifest-request":
		p, _ := d.Text(d.Member(0, "principal"))
		if string(p) == l.principal && l.published {
			return l.gossip.Have(l.emit, l.digest)
		}
		return l.sendControl(control.WriteMissing(l.writer(), string(p), true))
	case "identity-request":
		p, _ := d.Text(d.Member(0, "principal"))
		if string(p) == l.principal {
			return l.sendControl(l.chain.WriteDescriptor(l.writer()))
		}
		return l.sendControl(control.WriteMissing(l.writer(), string(p), false))
	case "":
		return control.ErrInvalid // Lite requires a kind.
	}
	return nil
}
