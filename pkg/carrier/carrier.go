// Package carrier frames messages on a link as kind u8, length u32BE and body,
// as wendy-lite components/wendy_net_peer/src/carrier.c does.
package carrier

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	KindControl  = 1
	KindDatagram = 2
	// The operator router mux uses kinds 5 and 4 with the same bodies.
	KindOperatorControl  = 5
	KindOperatorDatagram = 4

	HeaderSize    = 5
	ControlPrefix = 9
	// ControlMax is the control payload limit Lite's carrier accepts, peer.c wnc_init.
	ControlMax  = 65536
	DatagramMax = 1100 // WN_DATAGRAM_MAX
	// HelloMax bounds the hello preamble, WN_CONTROL_MAX.
	HelloMax = 2048
	// MaxFrameBuffer holds any control payload Lite writes with WN_CONTROL_MAX and any datagram.
	MaxFrameBuffer = 4 + 4096
)

var (
	ErrInvalid  = errors.New("carrier: invalid frame")
	ErrTooLarge = errors.New("carrier: payload too large")
)

// WriteHello sends the hello that precedes framing, a u32BE length then CBOR.
// See setup_hello in wendy-lite components/wendy_net_peer/src/peer.c.
func WriteHello(w io.Writer, hello []byte) error {
	if len(hello) == 0 || len(hello) > HelloMax {
		return ErrTooLarge
	}
	var buf [4 + HelloMax]byte
	binary.BigEndian.PutUint32(buf[:], uint32(len(hello)))
	n := 4 + copy(buf[4:], hello)
	_, err := w.Write(buf[:n])
	return err
}

// ReadHello reads the peer's hello preamble into buf and returns the CBOR.
func ReadHello(r io.Reader, buf []byte) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n == 0 || n > HelloMax || n > len(buf) {
		return nil, ErrInvalid
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Framer writes and reads frames. The zero value uses kinds 1 and 2 and ControlMax.
type Framer struct {
	// Operator selects kinds 5 and 4.
	Operator bool
	// ControlLimit bounds control payloads, ControlMax if zero.
	ControlLimit int
	// Dropped counts valid frames skipped because they did not fit the read buffer.
	Dropped int
	// buf holds one outgoing frame so it goes out in a single Write.
	buf [ControlPrefix + DatagramMax]byte
}

func (f *Framer) kinds() (control, datagram byte) {
	if f.Operator {
		return KindOperatorControl, KindOperatorDatagram
	}
	return KindControl, KindDatagram
}

func (f *Framer) limit() int {
	if f.ControlLimit > 0 {
		return f.ControlLimit
	}
	return ControlMax
}

// WriteControl sends one control payload.
func (f *Framer) WriteControl(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > f.limit() {
		return ErrTooLarge
	}
	control, _ := f.kinds()
	var hdr [ControlPrefix]byte
	hdr[0] = control
	binary.BigEndian.PutUint32(hdr[1:], uint32(4+len(payload)))
	binary.BigEndian.PutUint32(hdr[5:], uint32(len(payload)))
	if len(payload) <= len(f.buf)-ControlPrefix {
		n := copy(f.buf[:], hdr[:])
		n += copy(f.buf[n:], payload)
		_, err := w.Write(f.buf[:n])
		return err
	}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// WriteDatagram sends one datagram payload.
func (f *Framer) WriteDatagram(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > DatagramMax {
		return ErrTooLarge
	}
	_, datagram := f.kinds()
	f.buf[0] = datagram
	binary.BigEndian.PutUint32(f.buf[1:], uint32(len(payload)))
	n := HeaderSize + copy(f.buf[HeaderSize:], payload)
	_, err := w.Write(f.buf[:n])
	return err
}

// ReadFrame reads the next frame into buf, at least DatagramMax bytes. Unknown
// kinds and control frames larger than buf are skipped. payload points into buf.
func (f *Framer) ReadFrame(r io.Reader, buf []byte) (control bool, payload []byte, err error) {
	if len(buf) < DatagramMax {
		return false, nil, ErrTooLarge
	}
	controlKind, datagramKind := f.kinds()
	for {
		var hdr [HeaderSize]byte
		if _, err = io.ReadFull(r, hdr[:]); err != nil {
			return false, nil, err
		}
		size := int(binary.BigEndian.Uint32(hdr[1:]))
		switch hdr[0] {
		case controlKind:
			if size < 5 || size > f.limit()+4 {
				return false, nil, ErrInvalid
			}
		case datagramKind:
			if size == 0 || size > DatagramMax {
				return false, nil, ErrInvalid
			}
		default:
			if size > f.limit()+4 {
				return false, nil, ErrInvalid
			}
			if err = drain(r, buf, size); err != nil {
				return false, nil, err
			}
			continue
		}
		if size > len(buf) {
			f.Dropped++
			if err = drain(r, buf, size); err != nil {
				return false, nil, err
			}
			continue
		}
		body := buf[:size]
		if _, err = io.ReadFull(r, body); err != nil {
			return false, nil, err
		}
		if hdr[0] == datagramKind {
			return false, body, nil
		}
		if int(binary.BigEndian.Uint32(body)) != size-4 {
			return false, nil, ErrInvalid
		}
		return true, body[4:], nil
	}
}

func drain(r io.Reader, buf []byte, n int) error {
	for n > 0 {
		m, err := io.ReadFull(r, buf[:min(n, len(buf))])
		if err != nil {
			return err
		}
		n -= m
	}
	return nil
}
