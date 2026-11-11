// Package certwire describes and serves certificate chains in 1024 byte chunks,
// as wendy-lite components/wendy_net_peer/src/certificate_wire.c does.
package certwire

import (
	"errors"

	"github.com/hybridgroup/tink/pkg/cbor"
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/sha256"
)

const (
	ChainMax = 16   // WNCF_CHAIN_MAX
	Chunk    = 1024 // WNCF_CHUNK
)

var ErrInvalid = errors.New("certwire: invalid message")

// Chain is a local chain to describe and serve.
type Chain struct {
	Principal string
	certs     lcrypto.CertChain
	hashes    [ChainMax][32]byte
	n         int
}

// Configure hashes each DER part of certs, leaf first.
func (c *Chain) Configure(principal string, certs lcrypto.CertChain) error {
	n := certs.NumCerts()
	if n == 0 || n > ChainMax || len(principal) != 105 {
		return ErrInvalid
	}
	c.Principal, c.certs, c.n = principal, certs, n
	for i := range n {
		der, err := certs.CertView(i)
		if err != nil {
			return err
		}
		d := sha256.New()
		d.Write(der)
		d.Sum(c.hashes[i][:0])
	}
	return nil
}

// WriteDescriptor writes the certificate chain message with its hashes and principal.
func (c *Chain) WriteDescriptor(w *cbor.Writer) ([]byte, error) {
	if c.n == 0 {
		return nil, ErrInvalid
	}
	header(w, "chain")
	w.Map(2)
	w.Key("hashes")
	w.Array(c.n)
	for i := range c.n {
		w.Bytes(c.hashes[i][:])
	}
	w.Key("principal")
	w.Text(c.Principal)
	return w.Finish()
}

func header(w *cbor.Writer, kind string) {
	w.Map(2)
	w.Key("kind")
	w.Text("certificate")
	w.Key("certificate")
	w.Map(1)
	w.Key(kind)
}

// Request is a fetch of one part at Offset.
type Request struct {
	Hash   [32]byte
	Offset int
}

// Parse reads a certificate message. It returns which of chain, request,
// chunk or missing it holds and the token of that map.
func Parse(d *cbor.Doc) (kind string, obj int, err error) {
	if !d.Equal(d.Member(0, "kind"), "certificate") {
		return "", -1, ErrInvalid
	}
	c := d.Member(0, "certificate")
	for _, k := range [...]string{"chain", "request", "chunk", "missing"} {
		if t := d.Member(c, k); t >= 0 && d.Kind(t) == cbor.KindMap {
			return k, t, nil
		}
	}
	return "", -1, ErrInvalid
}

// ReadRequest decodes a request map.
func ReadRequest(d *cbor.Doc, obj int) (Request, error) {
	var q Request
	h, err := d.Bytes(d.Member(obj, "hash"))
	if err != nil || len(h) != 32 {
		return q, ErrInvalid
	}
	off, err := d.Uint(d.Member(obj, "offset"))
	if err != nil || off%Chunk != 0 || off > 1<<20 {
		return q, ErrInvalid
	}
	copy(q.Hash[:], h)
	q.Offset = int(off)
	return q, nil
}

// WriteRequest writes a request for one part.
func WriteRequest(w *cbor.Writer, q Request) ([]byte, error) {
	header(w, "request")
	w.Map(2)
	w.Key("hash")
	w.Bytes(q.Hash[:])
	w.Key("offset")
	w.Uint(uint64(q.Offset))
	return w.Finish()
}

// WriteMissing answers a request for a part this node does not hold.
func WriteMissing(w *cbor.Writer, q Request) ([]byte, error) {
	header(w, "missing")
	w.Map(2)
	w.Key("hash")
	w.Bytes(q.Hash[:])
	w.Key("offset")
	w.Uint(uint64(q.Offset))
	return w.Finish()
}

// WriteChunk writes part data at offset of a part with total length.
func WriteChunk(w *cbor.Writer, hash [32]byte, offset, total int, data []byte) ([]byte, error) {
	header(w, "chunk")
	w.Map(4)
	w.Key("data")
	w.Bytes(data)
	w.Key("hash")
	w.Bytes(hash[:])
	w.Key("total")
	w.Uint(uint64(total))
	w.Key("offset")
	w.Uint(uint64(offset))
	return w.Finish()
}

// Answer writes the chunk for q from c, or missing when c has no such part.
func (c *Chain) Answer(w *cbor.Writer, q Request) ([]byte, error) {
	for i := range c.n {
		if c.hashes[i] != q.Hash {
			continue
		}
		der, err := c.certs.CertView(i)
		if err != nil || q.Offset >= len(der) {
			break
		}
		end := min(q.Offset+Chunk, len(der))
		return WriteChunk(w, q.Hash, q.Offset, len(der), der[q.Offset:end])
	}
	return WriteMissing(w, q)
}
