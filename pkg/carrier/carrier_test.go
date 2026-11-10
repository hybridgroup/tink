package carrier

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var f Framer
	var stream bytes.Buffer
	ctl := bytes.Repeat([]byte{0xa1}, ControlMax)
	dg := bytes.Repeat([]byte{7}, DatagramMax)
	if err := f.WriteControl(&stream, ctl); err != nil {
		t.Fatal(err)
	}
	// A future kind is drained, as Lite does.
	stream.Write([]byte{9, 0, 0, 0, 3, 1, 2, 3})
	if err := f.WriteDatagram(&stream, dg); err != nil {
		t.Fatal(err)
	}
	if got := stream.Bytes()[:ControlPrefix]; !bytes.Equal(got, []byte{1, 0, 0, 8, 4, 0, 0, 8, 0}) {
		t.Fatalf("control header %x", got)
	}
	buf := make([]byte, MaxFrameBuffer)
	control, p, err := f.ReadFrame(&stream, buf)
	if err != nil || !control || !bytes.Equal(p, ctl) {
		t.Fatal("control", err)
	}
	control, p, err = f.ReadFrame(&stream, buf)
	if err != nil || control || !bytes.Equal(p, dg) {
		t.Fatal("datagram", err)
	}
}

func TestReject(t *testing.T) {
	var f Framer
	buf := make([]byte, MaxFrameBuffer)
	for _, frame := range [][]byte{
		{1, 0, 0, 0, 4, 0, 0, 0, 0},       // Control too short.
		{1, 0, 0, 0, 6, 0, 0, 0, 1, 9, 9}, // Inner length mismatch.
		{2, 0, 0, 0, 0},                   // Empty datagram.
		{2, 0, 0, 4, 0x4d},                // Datagram over 1100.
		{9, 0, 0, 8, 5},                   // Unknown kind over the control limit.
	} {
		if _, _, err := f.ReadFrame(bytes.NewReader(frame), buf); err == nil {
			t.Errorf("accepted %x", frame)
		}
	}
	if err := f.WriteDatagram(new(bytes.Buffer), make([]byte, DatagramMax+1)); err == nil {
		t.Error("wrote an oversized datagram")
	}
}

func TestOperatorKinds(t *testing.T) {
	f := Framer{Operator: true}
	var stream bytes.Buffer
	f.WriteControl(&stream, []byte{0xa0})
	f.WriteDatagram(&stream, []byte{1})
	b := stream.Bytes()
	if b[0] != 5 || b[ControlPrefix+1] != 4 {
		t.Fatalf("kinds %x", b)
	}
}
