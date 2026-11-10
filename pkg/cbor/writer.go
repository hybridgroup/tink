// Package cbor is the compact deterministic CBOR subset used by Wendy Net:
// definite maps and arrays, text, bytes, unsigned integers and booleans.
// Callers write map keys in a fixed order. It matches wendy-lite
// components/wendy_net_common/src/binary.c and components/wendy_net_peer/src/binary.c.
package cbor

import "errors"

var ErrWrite = errors.New("cbor: write past buffer or limit")

// Writer appends CBOR to a fixed buffer. Once a write fails all later writes
// are dropped and Finish returns ErrWrite.
type Writer struct {
	buf    []byte
	n      int
	max    int
	failed bool
}

// Reset makes w write into buf, at most max bytes when max is positive.
func (w *Writer) Reset(buf []byte, max int) {
	if max <= 0 || max > len(buf) {
		max = len(buf)
	}
	*w = Writer{buf: buf, max: max}
}

// Len returns the bytes written so far.
func (w *Writer) Len() int { return w.n }

// Finish returns the encoded bytes.
func (w *Writer) Finish() ([]byte, error) {
	if w.failed || w.n == 0 {
		return nil, ErrWrite
	}
	return w.buf[:w.n], nil
}

func (w *Writer) Raw(b []byte) {
	if w.failed || len(b) > w.max-w.n {
		w.failed = true
		return
	}
	w.n += copy(w.buf[w.n:], b)
}

func (w *Writer) head(major byte, v uint64) {
	var b [9]byte
	switch {
	case v < 24:
		b[0] = major<<5 | byte(v)
		w.Raw(b[:1])
		return
	case v <= 0xff:
		b[0] = major<<5 | 24
		b[1] = byte(v)
		w.Raw(b[:2])
		return
	case v <= 0xffff:
		b[0] = major<<5 | 25
		b[1], b[2] = byte(v>>8), byte(v)
		w.Raw(b[:3])
		return
	case v <= 0xffffffff:
		b[0] = major<<5 | 26
		for i := range 4 {
			b[1+i] = byte(v >> (8 * (3 - i)))
		}
		w.Raw(b[:5])
		return
	}
	b[0] = major<<5 | 27
	for i := range 8 {
		b[1+i] = byte(v >> (8 * (7 - i)))
	}
	w.Raw(b[:9])
}

func (w *Writer) Uint(v uint64) { w.head(0, v) }
func (w *Writer) Map(n int)     { w.head(5, uint64(n)) }
func (w *Writer) Array(n int)   { w.head(4, uint64(n)) }

func (w *Writer) Bytes(b []byte) {
	w.head(2, uint64(len(b)))
	w.Raw(b)
}

func (w *Writer) Text(s string) {
	w.head(3, uint64(len(s)))
	if w.failed || len(s) > w.max-w.n {
		w.failed = true
		return
	}
	w.n += copy(w.buf[w.n:], s)
}

func (w *Writer) Bool(v bool) {
	b := byte(0xf4)
	if v {
		b = 0xf5
	}
	w.Raw([]byte{b})
}

// Key writes the wire key of a schema field name, see KeyName.
func (w *Writer) Key(name string) { w.Text(KeyName(name)) }
