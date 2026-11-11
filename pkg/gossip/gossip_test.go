package gossip

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/hybridgroup/tink/pkg/cbor"
	"github.com/hybridgroup/tink/pkg/control"
)

// link connects two sessions through the control codec, like a carrier would.
type link struct {
	t     *testing.T
	queue [][]byte
}

func (l *link) emit(g *control.Gossip) error {
	buf := make([]byte, control.ControlMax)
	var w cbor.Writer
	w.Reset(buf, 0)
	b, err := control.WriteGossip(&w, g)
	if err != nil {
		l.t.Fatal(err)
	}
	l.queue = append(l.queue, b)
	return nil
}

func (l *link) deliver(s *Session, now uint64, done Complete, reply Emit) {
	for len(l.queue) > 0 {
		b := l.queue[0]
		l.queue = l.queue[1:]
		var d cbor.Doc
		if err := d.Parse(b); err != nil {
			l.t.Fatal(err)
		}
		var g control.Gossip
		if err := control.ReadGossip(&d, &g); err != nil {
			l.t.Fatal(err)
		}
		if err := s.Receive(&g, now, reply, done); err != nil {
			l.t.Fatal(err)
		}
	}
}

func TestIdentify(t *testing.T) {
	data := []byte("manifest bytes")
	pre := append([]byte("wendy-mesh-artifact/1\x00"), 1, 0, 0, 0, byte(len(data)))
	pre = append(pre, data...)
	if Identify(1, data) != sha256.Sum256(pre) {
		t.Fatal("digest preimage")
	}
}

func TestTransfer(t *testing.T) {
	a, b := &Session{Type: 1}, &Session{Type: 1}
	ab, ba := &link{t: t}, &link{t: t}
	body := bytes.Repeat([]byte("0123456789abcdef"), 200) // 3200 bytes, 4 chunks.
	id := a.Offer(body, 1000)
	if err := a.Have(ab.emit, id); err != nil {
		t.Fatal(err)
	}
	var got []byte
	done := func(typ uint8, digest [32]byte, data []byte) {
		if digest != id {
			t.Fatal("digest")
		}
		got = append([]byte(nil), data...)
	}
	none := func(uint8, [32]byte, []byte) { t.Fatal("unexpected completion") }
	ab.deliver(b, 1, done, ba.emit) // HAVE, b answers WANT.
	ba.deliver(a, 1, none, ab.emit) // WANT starts the upload.
	for i := 0; i < 10 && got == nil; i++ {
		if err := a.Poll(2, ab.emit); err != nil {
			t.Fatal(err)
		}
		ab.deliver(b, 2, done, ba.emit)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %d bytes", len(got))
	}
	if a.Busy() || b.Busy() {
		t.Fatal("sessions still busy")
	}
}

func TestUnavailable(t *testing.T) {
	a, b := &Session{Type: 1}, &Session{Type: 1}
	ab, ba := &link{t: t}, &link{t: t}
	var digest [32]byte
	digest[0] = 1
	b.Have(ab.emit, digest) // b claims something it does not have.
	none := func(uint8, [32]byte, []byte) { t.Fatal("unexpected completion") }
	ab.deliver(a, 1, none, ba.emit)
	if len(ba.queue) != 1 {
		t.Fatal("no WANT")
	}
	ba.deliver(b, 1, none, ab.emit)
	if len(ab.queue) != 1 {
		t.Fatal("no UNAVAILABLE")
	}
	ab.deliver(a, 1, none, ba.emit)
	if a.findFetch(digest) != nil {
		t.Fatal("fetch kept after UNAVAILABLE")
	}
}

func TestBadDigest(t *testing.T) {
	b := &Session{Type: 1}
	var digest [32]byte
	sent := 0
	emit := func(*control.Gossip) error { sent++; return nil }
	none := func(uint8, [32]byte, []byte) { t.Fatal("completed a body with a wrong digest") }
	b.Receive(&control.Gossip{Op: control.OpHave, Type: 1, Digest: digest}, 0, emit, none)
	f := b.findFetch(digest)
	data := make([]byte, 10)
	err := b.Receive(&control.Gossip{Op: control.OpData, Type: 1, Digest: digest, Request: f.request,
		Total: 10, Data: data}, 0, emit, none)
	if err != ErrDigest {
		t.Fatalf("got %v", err)
	}
}

func TestIdle(t *testing.T) {
	b := &Session{Type: 1}
	var digest [32]byte
	emit := func(*control.Gossip) error { return nil }
	b.Receive(&control.Gossip{Op: control.OpHave, Type: 1, Digest: digest}, 0, emit, nil)
	b.Poll(IdleMS, emit)
	if b.findFetch(digest) != nil {
		t.Fatal("idle fetch kept")
	}
}

// TestRepublishReusesBuffer checks that forgetting a manifest and offering
// its successor of the same size allocates nothing, as a leaf does every 300 s.
func TestRepublishReusesBuffer(t *testing.T) {
	s := &Session{Type: 1}
	body := bytes.Repeat([]byte{1}, 600)
	id := s.Offer(body, 1000)
	allocs := testing.AllocsPerRun(20, func() {
		s.Forget(id)
		body[0]++
		id = s.Offer(body, 1000)
	})
	if allocs != 0 {
		t.Fatalf("%v allocations per republish", allocs)
	}
	used := 0
	for i := range s.objects {
		if s.objects[i].used {
			used++
		}
	}
	if used != 1 {
		t.Fatalf("%d objects in use", used)
	}
}

func TestOfferEvictsEarliest(t *testing.T) {
	s := &Session{Type: 1}
	for i := range MaxObjects {
		s.Offer([]byte{byte(i)}, uint64(100+i))
	}
	newest := s.Offer([]byte{9}, 500)
	if s.find(Identify(1, []byte{0}), 0) != nil || s.find(newest, 0) == nil {
		t.Fatal("did not replace the object that expires first")
	}
}
