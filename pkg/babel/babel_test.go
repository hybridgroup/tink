package babel

import (
	"bytes"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
	"github.com/hybridgroup/tink/pkg/addr"
)

func prefix(t *testing.T) [16]byte {
	u, err := addr.ParseUUID(litegolden.Peer)
	if err != nil {
		t.Fatal(err)
	}
	return u.Address()
}

func body(p *Packet) []byte { return p.Bytes()[4:] }

func TestEncodeMatchesLite(t *testing.T) {
	pfx := prefix(t)
	for _, tc := range []struct {
		name string
		add  func(*Packet)
	}{
		{"babel-hello", func(p *Packet) { p.Hello(0x1234, 400) }},
		{"babel-ihu", func(p *Packet) { p.IHU(96, 800) }},
		{"babel-update", func(p *Packet) { p.Update(0x0102030405060708, pfx, 128, 513, 0, 1600) }},
		{"babel-retract", func(p *Packet) { p.Update(0x0102030405060708, pfx, 128, 513, Infinity, 1600) }},
		{"babel-request-wildcard", func(p *Packet) { p.WildcardRequest() }},
		{"babel-ack", func(p *Packet) { p.Ack(0xbeef) }},
	} {
		var p Packet
		p.Reset()
		tc.add(&p)
		if got, want := body(&p), litegolden.Get(tc.name); !bytes.Equal(got, want) {
			t.Errorf("%s\n got %x\nwant %x", tc.name, got, want)
		}
	}
}

func wrap(tlvs ...[]byte) []byte {
	b := []byte{42, 2, 0, 0}
	for _, t := range tlvs {
		b = append(b, t...)
	}
	n := len(b) - 4
	b[2], b[3] = byte(n>>8), byte(n)
	return b
}

func TestDecodeLite(t *testing.T) {
	pfx := prefix(t)
	var got []Message
	pkt := wrap(litegolden.Get("babel-hello-unicast"), []byte{0}, litegolden.Get("babel-update"),
		litegolden.Get("babel-seqrequest"), litegolden.Get("babel-ackrequest"), litegolden.Get("babel-request-wildcard"))
	if err := Decode(pkt, func(m *Message) { got = append(got, *m) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("%d messages", len(got))
	}
	if h := got[0]; h.Type != TypeHello || !h.Unicast || h.Seqno != 0x1234 || h.Interval != 400 {
		t.Errorf("hello %+v", h)
	}
	if u := got[1]; u.Type != TypeUpdate || u.Router != 0x0102030405060708 || u.Prefix != pfx || u.Bits != 128 || u.Seqno != 513 {
		t.Errorf("update %+v", u)
	}
	if s := got[2]; s.Type != TypeSeqRequest || s.Seqno != 514 || s.Hops != 16 || s.Prefix != pfx {
		t.Errorf("seqrequest %+v", s)
	}
	if a := got[3]; a.Type != TypeAckRequest || a.Opaque != 0xbeef || a.Interval != 200 {
		t.Errorf("ackrequest %+v", a)
	}
	if r := got[4]; r.Type != TypeRequest || !r.Wildcard {
		t.Errorf("request %+v", r)
	}
	if Decode([]byte{42, 2, 0, 9, 4}, func(*Message) {}) == nil {
		t.Error("accepted a truncated packet")
	}
}

func TestSpeaker(t *testing.T) {
	pfx := prefix(t)
	s := Speaker{Router: 7, Prefix: pfx, Seqno: 513}
	var p Packet
	s.Poll(&p, 0)
	var types []uint8
	Decode(p.Bytes(), func(m *Message) {
		types = append(types, m.Type)
		if m.Type == TypeIHU && m.Metric != Infinity {
			t.Error("IHU finite before any Hello was heard")
		}
	})
	if !bytes.Equal(types, []byte{TypeHello, TypeIHU, TypeUpdate}) {
		t.Fatalf("first poll %v", types)
	}
	// The router's Hello and IHU bring the link up.
	var in Packet
	in.Reset()
	in.Hello(1, 400)
	in.IHU(128, 800)
	in.WildcardRequest()
	s.Receive(in.Bytes(), 100)
	if !s.Up(100) || s.Up(100+14001) {
		t.Fatal("link state")
	}
	s.Poll(&p, 100)
	types = types[:0]
	Decode(p.Bytes(), func(m *Message) {
		types = append(types, m.Type)
		if m.Type == TypeIHU && m.Metric != LANCost {
			t.Error("IHU cost after hearing a Hello")
		}
	})
	// The first Hello heard brings an IHU now, and the wildcard request an Update.
	if !bytes.Equal(types, []byte{TypeIHU, TypeUpdate}) {
		t.Fatalf("second poll %v", types)
	}
	// A seqno request for our prefix asks for a new manifest.
	var sr Packet
	sr.Reset()
	sr.tlv(TypeSeqRequest, append([]byte{2, 128, 2, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 7}, pfx[:]...))
	s.Receive(sr.Bytes(), 200)
	if !s.SeqnoWanted {
		t.Fatal("seqno request ignored")
	}
}
