package certwire

import (
	"bytes"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
	"github.com/hybridgroup/tink/pkg/cbor"
)

// hashChain serves fixed hashes, as gen.c describes them.
type hashChain [][]byte

func (h hashChain) NumCerts() int                       { return len(h) }
func (h hashChain) Cert(dst []byte, i int) (int, error) { return copy(dst, h[i]), nil }
func (h hashChain) CertView(i int) ([]byte, error)      { return h[i], nil }

func newWriter() *cbor.Writer {
	var w cbor.Writer
	w.Reset(make([]byte, 4096), 0)
	return &w
}

func TestMatchesLite(t *testing.T) {
	principal := string(litegolden.Get("principal"))
	c := Chain{Principal: principal, n: 2}
	for i := range 32 {
		c.hashes[0][i], c.hashes[1][i] = byte(i), byte(0x80+i)
	}
	got, err := c.WriteDescriptor(newWriter())
	if err != nil || !bytes.Equal(got, litegolden.Get("cert-chain")) {
		t.Fatalf("chain %x %v", got, err)
	}
	q := Request{Hash: c.hashes[1], Offset: 1024}
	if got, _ := WriteRequest(newWriter(), q); !bytes.Equal(got, litegolden.Get("cert-request")) {
		t.Fatalf("request %x", got)
	}
	if got, _ := WriteMissing(newWriter(), q); !bytes.Equal(got, litegolden.Get("cert-missing")) {
		t.Fatalf("missing %x", got)
	}
	data := make([]byte, 76)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}
	if got, _ := WriteChunk(newWriter(), q.Hash, 1024, 1100, data); !bytes.Equal(got, litegolden.Get("cert-chunk")) {
		t.Fatalf("chunk %x", got)
	}
	var d cbor.Doc
	if err := d.Parse(litegolden.Get("cert-request")); err != nil {
		t.Fatal(err)
	}
	kind, obj, err := Parse(&d)
	if err != nil || kind != "request" {
		t.Fatal(kind, err)
	}
	if back, err := ReadRequest(&d, obj); err != nil || back != q {
		t.Fatal(back, err)
	}
}

func TestAnswer(t *testing.T) {
	part := bytes.Repeat([]byte{0x30}, 1500)
	var c Chain
	if err := c.Configure(string(litegolden.Get("principal")), hashChain{part}); err != nil {
		t.Fatal(err)
	}
	b, err := c.Answer(newWriter(), Request{Hash: c.hashes[0], Offset: 1024})
	if err != nil {
		t.Fatal(err)
	}
	var d cbor.Doc
	d.Parse(b)
	kind, obj, _ := Parse(&d)
	data, _ := d.Bytes(d.Member(obj, "data"))
	if kind != "chunk" || len(data) != 476 {
		t.Fatal(kind, len(data))
	}
	b, _ = c.Answer(newWriter(), Request{Offset: 0})
	d.Parse(b)
	if kind, _, _ := Parse(&d); kind != "missing" {
		t.Fatal(kind)
	}
}
