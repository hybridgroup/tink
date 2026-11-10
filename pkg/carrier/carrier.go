// Package carrier frames control and datagram messages on a Wendy Net link
// stream, as wendy-lite components/wendy_net_peer/src/carrier.c does.
//
// Each frame is kind u8 | length u32BE | body. A control body starts with
// its own u32BE length followed by CBOR. A datagram body is opaque.
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

	HeaderSize     = 5
	ControlPrefix  = 9
	ControlMax     = 2048 // WN_CONTROL_MAX
	DatagramMax    = 1100 // WN_DATAGRAM_MAX
	MaxFrameBuffer = ControlPrefix + ControlMax
)

var (
	ErrInvalid  = errors.New("carrier: invalid frame")
	ErrTooLarge = errors.New("carrier: payload too large")
)

// Framer writes and reads frames. The zero value uses kinds 1 and 2 and ControlMax.
type Framer struct {
	// Operator selects kinds 5 and 4.
	Operator bool
	// ControlLimit bounds control payloads, ControlMax if zero.
	ControlLimit int
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

// ReadFrame reads the next control or datagram frame into buf, which must
// hold MaxFrameBuffer bytes. Frames of unknown kind are drained and skipped,
// as Lite does. The payload points into buf.
func (f *Framer) ReadFrame(r io.Reader, buf []byte) (control bool, payload []byte, err error) {
	if len(buf) < 4+f.limit() || len(buf) < DatagramMax {
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
			if _, err = io.ReadFull(r, buf[:size]); err != nil {
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
