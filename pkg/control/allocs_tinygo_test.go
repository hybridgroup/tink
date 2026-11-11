//go:build tinygo

package control

import (
	"runtime"
	"testing"

	"github.com/hybridgroup/tink/pkg/cbor"
)

func TestReadGossipAllocs(t *testing.T) {
	var w cbor.Writer
	w.Reset(make([]byte, 512), 0)
	b, _ := WriteGossip(&w, &Gossip{Op: OpWant, Type: 1, Request: 9})
	b = append([]byte(nil), b...)
	var d cbor.Doc
	var g Gossip
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	before := m.Mallocs
	for range 10 {
		d.Parse(b)
		ReadGossip(&d, &g)
	}
	runtime.ReadMemStats(&m)
	if n := (m.Mallocs - before) / 10; n != 0 {
		t.Fatalf("%d allocations per parse and read", n)
	}
}
