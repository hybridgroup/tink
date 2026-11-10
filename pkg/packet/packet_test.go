package packet

import (
	"bytes"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
)

func litePacket() []byte {
	p := make([]byte, MTU)
	p[0] = 0x60
	p[4], p[5] = (MTU-40)>>8, (MTU-40)&0xff
	for i := 8; i < len(p); i++ {
		p[i] = byte(i * 13)
	}
	return p
}

func TestFragmentMatchesLite(t *testing.T) {
	p := litePacket()
	var out [DatagramMax]byte
	for i, off := range []int{0, FragmentData} {
		n, err := Fragment(&out, p, 0xdeadbeef, off)
		if err != nil {
			t.Fatal(err)
		}
		want := litegolden.Get([]string{"fragment-0", "fragment-1"}[i])
		if !bytes.Equal(out[:n], want) {
			t.Fatalf("fragment %d differs", i)
		}
	}
}

func TestAssemble(t *testing.T) {
	var s Assembler
	a, b := litegolden.Get("fragment-1"), litegolden.Get("fragment-0")
	if p, err := s.Add(a, 0); p != nil || err != nil {
		t.Fatal(p, err)
	}
	if p, err := s.Add([]byte{KindBabel, 1, 2}, 1); p != nil || err != nil {
		t.Fatal("babel datagram disturbed reassembly", err)
	}
	p, err := s.Add(b, 2)
	if err != nil || !bytes.Equal(p, litePacket()) {
		t.Fatal("reassembly failed", err)
	}
	if _, err := s.Add(a, reassemblyUS+10); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(a, reassemblyUS+11); err == nil {
		t.Fatal("accepted a duplicate fragment")
	}
}

func TestSmallPacket(t *testing.T) {
	p := make([]byte, 60)
	p[0], p[5] = 0x60, 20
	var out [DatagramMax]byte
	n, err := Fragment(&out, p, 7, 0)
	if err != nil {
		t.Fatal(err)
	}
	var s Assembler
	got, err := s.Add(out[:n], 0)
	if err != nil || !bytes.Equal(got, p) {
		t.Fatal(err)
	}
}
