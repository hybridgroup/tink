//go:build tinygo

package link

import (
	"runtime"
	"testing"
	"time"

	"github.com/hybridgroup/tink/pkg/babel"
	"github.com/hybridgroup/tink/pkg/cbor"
	"github.com/hybridgroup/tink/pkg/control"
)

type discard struct{}

func (discard) Read(b []byte) (int, error)  { return 0, nil }
func (discard) Write(b []byte) (int, error) { return len(b), nil }

func mallocs() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Mallocs
}

// TestSteadyStateAllocs keeps the running session free of heap allocations,
// which a 30 minute soak on the ESP32-S3 showed it cannot afford.
func TestSteadyStateAllocs(t *testing.T) {
	cred, _ := credential(t, leafID)
	l, err := New(Config{Tenant: tenant, Self: leafID, Peer: rtrID, Credential: cred, RouterID: 0x77,
		NowMS: func() int64 { return time.Now().UnixMilli() }})
	if err != nil {
		t.Fatal(err)
	}
	l.rw = discard{}
	l.start = time.Now()
	l.publish()

	var p babel.Packet
	p.Reset()
	p.Hello(1, 400)
	p.IHU(128, 800)
	dg := append([]byte(nil), p.Datagram()...)
	var w cbor.Writer
	w.Reset(make([]byte, 512), 0)
	want, _ := control.WriteGossip(&w, &control.Gossip{Op: control.OpWant, Type: 1, Digest: l.digest, Request: 9})
	want = append([]byte(nil), want...)

	for _, tc := range []struct {
		name string
		max  uint64
		f    func()
	}{
		// lcrypto's P-256 ScalarBaseMult allocates once per signature.
		{"publish", 1, func() { l.publish() }},
		{"babel in", 0, func() { l.handleDatagram(dg) }},
		{"poll", 0, func() { l.poll() }},
		{"want and upload", 0, func() { l.handleControl(want); l.poll() }},
	} {
		tc.f() // Warm up buffers.
		before := mallocs()
		for range 10 {
			tc.f()
		}
		if got := (mallocs() - before) / 10; got > tc.max {
			t.Errorf("%s: %d allocations per call, want at most %d", tc.name, got, tc.max)
		}
	}
}
