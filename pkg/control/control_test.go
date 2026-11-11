package control

import (
	"bytes"
	"errors"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/cbor"
)

func uuid(t *testing.T, s string) addr.UUID {
	t.Helper()
	u, err := addr.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestHelloMatchesLite(t *testing.T) {
	self, peer := uuid(t, litegolden.Self), uuid(t, litegolden.Peer)
	var buf [ControlMax]byte
	var w cbor.Writer
	w.Reset(buf[:], 0)
	got, err := WriteHello(&w, self, peer)
	if err != nil {
		t.Fatal(err)
	}
	want := litegolden.Get("hello")
	if !bytes.Equal(got, want) {
		t.Fatalf("hello\n got %x\nwant %x", got, want)
	}
	var d cbor.Doc
	if err := d.Parse(want); err != nil {
		t.Fatal(err)
	}
	// The Lite hello is from Self to Peer, so Peer checks it.
	if err := CheckHello(&d, peer, self); err != nil {
		t.Fatal(err)
	}
	if err := CheckHello(&d, self, peer); err == nil {
		t.Fatal("accepted a hello addressed to the sender")
	}
}

func TestHelloRole(t *testing.T) {
	self, peer := uuid(t, litegolden.Self), uuid(t, litegolden.Peer)
	for _, tc := range []struct {
		role string
		ok   bool
	}{{"", true}, {"router", true}, {"leaf", false}} {
		var buf [256]byte
		var w cbor.Writer
		w.Reset(buf[:], 0)
		w.Map(2)
		w.Key("kind")
		w.Text("hello")
		w.Key("hello")
		w.Map(6)
		w.Key("mtu")
		w.Uint(MTU)
		w.Key("peer")
		w.Text(self.String())
		w.Key("device")
		w.Text(peer.String())
		w.Key("version")
		w.Uint(1)
		w.Key("datagram")
		w.Uint(DatagramMax)
		w.Key("role")
		w.Text(tc.role)
		b, _ := w.Finish()
		var d cbor.Doc
		if err := d.Parse(b); err != nil {
			t.Fatal(err)
		}
		if err := CheckHello(&d, self, peer); (err == nil) != tc.ok {
			t.Errorf("role %q: %v", tc.role, err)
		}
	}
}

func TestRequestsMatchLite(t *testing.T) {
	principal := string(litegolden.Get("principal"))
	var buf [ControlMax]byte
	var w cbor.Writer
	for _, tc := range []struct {
		name  string
		write func() ([]byte, error)
	}{
		{"identity-request", func() ([]byte, error) { return WriteIdentityRequest(&w, principal) }},
		{"manifest-request", func() ([]byte, error) { return WriteManifestRequest(&w, principal) }},
		{"manifest-missing", func() ([]byte, error) { return WriteMissing(&w, principal, true) }},
		{"identity-missing", func() ([]byte, error) { return WriteMissing(&w, principal, false) }},
	} {
		w.Reset(buf[:], 0)
		got, err := tc.write()
		if err != nil {
			t.Fatal(err)
		}
		if want := litegolden.Get(tc.name); !bytes.Equal(got, want) {
			t.Errorf("%s\n got %x\nwant %x", tc.name, got, want)
		}
	}
}

func TestGossipMatchesLite(t *testing.T) {
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(0xa0 + i)
	}
	chunk := make([]byte, Chunk)
	for i := range chunk {
		chunk[i] = byte(i*7 + 3)
	}
	for _, tc := range []struct {
		name string
		g    Gossip
	}{
		{"gossip-have", Gossip{Op: OpHave, Type: 1, Digest: digest}},
		{"gossip-want", Gossip{Op: OpWant, Type: 1, Digest: digest, Request: 0x1234567890}},
		{"gossip-data", Gossip{Op: OpData, Type: 1, Digest: digest, Request: 0x1234567890,
			Offset: 1024, Total: 1500, Data: chunk[:476]}},
	} {
		var buf [ControlMax]byte
		var w cbor.Writer
		w.Reset(buf[:], 0)
		got, err := WriteGossip(&w, &tc.g)
		if err != nil {
			t.Fatal(tc.name, err)
		}
		want := litegolden.Get(tc.name)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s\n got %x\nwant %x", tc.name, got, want)
		}
		var d cbor.Doc
		if err := d.Parse(want); err != nil {
			t.Fatal(err)
		}
		var back Gossip
		if err := ReadGossip(&d, &back); err != nil {
			t.Fatal(tc.name, err)
		}
		if back.Op != tc.g.Op || back.Digest != tc.g.Digest || back.Request != tc.g.Request ||
			back.Offset != tc.g.Offset || back.Total != tc.g.Total || !bytes.Equal(back.Data, tc.g.Data) {
			t.Fatalf("%s: round trip %+v", tc.name, back)
		}
	}
}

func TestGossipFuture(t *testing.T) {
	var buf [256]byte
	var w cbor.Writer
	w.Reset(buf[:], 0)
	w.Map(2)
	w.Key("kind")
	w.Text("gossip")
	w.Key("gossip")
	w.Map(2)
	w.Key("v")
	w.Uint(2)
	w.Key("op")
	w.Text("have")
	b, _ := w.Finish()
	var d cbor.Doc
	if err := d.Parse(b); err != nil {
		t.Fatal(err)
	}
	var g Gossip
	if err := ReadGossip(&d, &g); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestGossipValidate(t *testing.T) {
	bad := []Gossip{
		{Op: OpHave, Type: 1, Request: 1},
		{Op: OpWant, Type: 1},
		{Op: OpData, Type: 1, Request: 1, Total: 2048, Offset: 1000, Data: make([]byte, 1024)},
		{Op: OpData, Type: 1, Request: 1, Total: 2048, Offset: 0, Data: make([]byte, 1000)},
		{Op: OpData, Type: 1, Request: 1, Total: ObjectMax + 1, Data: make([]byte, 1024)},
		{Op: OpHave, Type: 4},
	}
	for i, g := range bad {
		if g.Validate() == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestKind(t *testing.T) {
	var d cbor.Doc
	if err := d.Parse(litegolden.Get("hello")); err != nil {
		t.Fatal(err)
	}
	if Kind(&d) != "hello" {
		t.Fatal("kind")
	}
	if err := d.Parse([]byte{0xa0}); err != nil {
		t.Fatal(err)
	}
	if Kind(&d) != "" {
		t.Fatal("kind of empty map")
	}
}
