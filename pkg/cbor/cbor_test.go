package cbor

import (
	"bytes"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
)

func TestParseLiteVectors(t *testing.T) {
	for _, name := range []string{"hello", "identity-request", "gossip-data", "manifest-body", "manifest-body-plain"} {
		var d Doc
		if err := d.Parse(litegolden.Get(name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestManifestMembers(t *testing.T) {
	var d Doc
	if err := d.Parse(litegolden.Get("manifest-body")); err != nil {
		t.Fatal(err)
	}
	if v, err := d.Uint(d.Member(0, "agentPort")); err != nil || v != 43024 {
		t.Fatal("agentPort", v, err)
	}
	if !d.Equal(d.Member(0, "name"), "kitchen") || !d.Equal(d.Member(0, "platform"), "Lite") {
		t.Fatal("text members")
	}
	route := d.Member(0, "route")
	if v, err := d.Uint(d.Member(route, "routerId")); err != nil || v != 0x0102030405060708 {
		t.Fatal("routerId", v, err)
	}
	apps := d.Member(0, "appEndpoints")
	if d.Len(apps) != 1 {
		t.Fatal("appEndpoints length")
	}
	if v, err := d.Uint(d.Member(d.Elem(apps, 0), "port")); err != nil || v != 43025 {
		t.Fatal("app port", v, err)
	}
	if !d.Equal(d.Elem(d.Member(0, "caps"), 0), "sensors") {
		t.Fatal("caps")
	}
	if v, _ := d.Uint(d.Member(0, "version")); v != 4 {
		t.Fatal("version", v)
	}
	if !d.Fields(0, "agentPort", "revision", "agentTransport", "appEndpoints", "caps", "device",
		"Expires", "Issued", "platform", "name", "route", "services", "version") {
		t.Fatal("fields")
	}
}

func TestReject(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"non minimal", []byte{0x18, 0x05}},
		{"non minimal 16", []byte{0x19, 0x00, 0xff}},
		{"indefinite", []byte{0x9f, 0xff}},
		{"float", []byte{0xf9, 0x3c, 0x00}},
		{"tag", []byte{0xc1, 0x00}},
		{"duplicate key", []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}},
		{"bytes key", []byte{0xa1, 0x41, 'a', 0x01}},
		{"bad utf8", []byte{0x62, 0xc0, 0x80}},
		{"surrogate", []byte{0x63, 0xed, 0xa0, 0x80}},
		{"trailing", []byte{0x01, 0x02}},
		{"truncated", []byte{0x62, 'a'}},
		{"empty", nil},
	} {
		var d Doc
		if d.Parse(tc.b) == nil {
			t.Errorf("%s accepted", tc.name)
		}
	}
}

func TestLimits(t *testing.T) {
	deep := make([]byte, 0, 32)
	for range maxDepth + 1 {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0x00)
	var d Doc
	if d.Parse(deep) == nil {
		t.Error("accepted depth 17")
	}
	if d.Parse(deep[1:]) != nil {
		t.Error("rejected depth 16")
	}
	tokens := []byte{0x98, MaxTokens}
	for range MaxTokens {
		tokens = append(tokens, 0x00)
	}
	if d.Parse(tokens) == nil {
		t.Error("accepted more than MaxTokens tokens")
	}
}

func TestWriterRoundTrip(t *testing.T) {
	var buf [64]byte
	var w Writer
	w.Reset(buf[:], 0)
	w.Map(3)
	w.Key("version")
	w.Uint(1 << 40)
	w.Key("data")
	w.Bytes([]byte{1, 2, 3})
	w.Key("live")
	w.Bool(true)
	b, err := w.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var d Doc
	if err := d.Parse(b); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Uint(d.Member(0, "version")); v != 1<<40 {
		t.Fatal(v)
	}
	if d.Kind(d.Member(0, "live")) != KindTrue {
		t.Fatal("bool")
	}
	w.Reset(buf[:4], 0)
	w.Text("too long")
	if _, err := w.Finish(); err == nil {
		t.Fatal("overflow not reported")
	}
}

func TestKeyName(t *testing.T) {
	for i := 1; i < len(keyTable); i++ {
		if keyTable[i-1].name >= keyTable[i].name {
			t.Fatalf("table not sorted at %s", keyTable[i].name)
		}
	}
	for name, key := range map[string]string{"Expires": "e", "agentPort": "P", "owner": "o", "x": "x", "unknownField": "unknownField"} {
		if got := KeyName(name); got != key {
			t.Errorf("%s: %s", name, got)
		}
	}
}

func TestWriterHeads(t *testing.T) {
	var buf [64]byte
	var w Writer
	w.Reset(buf[:], 0)
	w.Array(6)
	for _, v := range []uint64{23, 0xff, 0xffff, 0xffffffff} {
		w.Uint(v)
	}
	w.TextBytes([]byte("hi"))
	w.Bytes([]byte{9})
	if w.Len() != 1+1+2+3+5+3+2 {
		t.Fatal("len", w.Len())
	}
	b, err := w.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var d Doc
	if err := d.Parse(b); err != nil {
		t.Fatal(err)
	}
	for k, want := range []uint64{23, 0xff, 0xffff, 0xffffffff} {
		if v, err := d.Uint(d.Elem(0, k)); err != nil || v != want {
			t.Fatal(k, v, err)
		}
	}
	if !d.Equal(d.Elem(0, 4), "hi") {
		t.Fatal("text bytes")
	}
	if v, err := d.Bytes(d.Elem(0, 5)); err != nil || !bytes.Equal(v, []byte{9}) {
		t.Fatal("bytes", v, err)
	}
	if _, err := d.Bytes(d.Elem(0, 4)); err != ErrType {
		t.Fatal("bytes of text", err)
	}
	if !bytes.Equal(d.Raw(d.Elem(0, 5)), []byte{0x41, 9}) || !bytes.Equal(d.Raw(0), b) {
		t.Fatal("raw")
	}
	if d.Raw(-1) != nil || d.Kind(99) != KindInvalid || d.Elem(0, 6) != -1 || d.Elem(1, 0) != -1 {
		t.Fatal("out of range")
	}
	w.Reset(buf[:2], 0)
	w.Raw([]byte{1, 2, 3})
	if _, err := w.Finish(); err == nil {
		t.Fatal("raw overflow not reported")
	}
}
