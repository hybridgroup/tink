//go:build tinygo

package manifest

import (
	"runtime"
	"testing"

	"github.com/hybridgroup/tink/pkg/cbor"
)

func TestBodyWriteAllocs(t *testing.T) {
	b := liteBody(t)
	b.Name = ""
	buf := make([]byte, BodyMax)
	var w cbor.Writer
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	before := m.Mallocs
	for range 10 {
		w.Reset(buf, 0)
		b.Write(&w)
	}
	runtime.ReadMemStats(&m)
	if n := (m.Mallocs - before) / 10; n != 0 {
		t.Fatalf("%d allocations per Body.Write", n)
	}
}
