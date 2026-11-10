// Package babel is the minimal Babel (RFC 8966) speaker a Wendy Net leaf
// needs on its one link. The codec follows wendy-lite components/wendy_babel/src/wire.c.
//
// A leaf announces only its own /128 and, like Lite's local_only engine,
// ignores routes from the neighbour: the link is its default route.
package babel

import (
	"encoding/binary"
	"errors"
)

// TLV types, RFC 8966 4.6.
const (
	TypePad1       = 0
	TypeAckRequest = 2
	TypeAck        = 3
	TypeHello      = 4
	TypeIHU        = 5
	TypeRouterID   = 6
	TypeNextHop    = 7
	TypeUpdate     = 8
	TypeRequest    = 9
	TypeSeqRequest = 10

	Infinity = 0xffff
	// PacketMax is WB_PACKET_MAX.
	PacketMax = 1099
	// DatagramKind prefixes a Babel packet in a carrier datagram.
	DatagramKind = 2
	magic        = 42
	version      = 2
)

var ErrInvalid = errors.New("babel: invalid packet")

// Message is one decoded TLV.
type Message struct {
	Type     uint8
	Unicast  bool
	Wildcard bool
	Seqno    uint16
	Interval uint16 // Centiseconds.
	Metric   uint16 // rxcost for IHU.
	Opaque   uint16
	Hops     uint8
	Router   uint64
	Prefix   [16]byte
	Bits     uint8
	// Family of Prefix: 6, 4, or 0 for none.
	Family uint8
}

// Packet builds one Babel packet.
type Packet struct {
	buf [PacketMax]byte
	n   int
}

// Reset starts an empty packet.
func (p *Packet) Reset() {
	p.buf[0], p.buf[1] = magic, version
	p.n = 4
}

// Bytes returns the packet with its body length set.
func (p *Packet) Bytes() []byte {
	binary.BigEndian.PutUint16(p.buf[2:], uint16(p.n-4))
	return p.buf[:p.n]
}

// Empty reports whether no TLV was added.
func (p *Packet) Empty() bool { return p.n <= 4 }

func (p *Packet) tlv(typ uint8, body []byte) bool {
	if len(body) > 255 || p.n+2+len(body) > len(p.buf) {
		return false
	}
	p.buf[p.n], p.buf[p.n+1] = typ, byte(len(body))
	p.n += 2 + copy(p.buf[p.n+2:], body)
	return true
}

// Hello adds a multicast Hello. interval is in centiseconds.
func (p *Packet) Hello(seqno, interval uint16) bool {
	var b [6]byte
	binary.BigEndian.PutUint16(b[2:], seqno)
	binary.BigEndian.PutUint16(b[4:], interval)
	return p.tlv(TypeHello, b[:])
}

// IHU adds an IHU with no address (AE 0).
func (p *Packet) IHU(rxcost, interval uint16) bool {
	var b [6]byte
	binary.BigEndian.PutUint16(b[2:], rxcost)
	binary.BigEndian.PutUint16(b[4:], interval)
	return p.tlv(TypeIHU, b[:])
}

// Ack answers an Ack Request.
func (p *Packet) Ack(opaque uint16) bool {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], opaque)
	return p.tlv(TypeAck, b[:])
}

// Update adds Router-Id then an IPv6 Update of prefix/bits, as wb_encode
// writes them. A metric of Infinity retracts the route and has no Router-Id.
func (p *Packet) Update(router uint64, prefix [16]byte, bits uint8, seqno, metric, interval uint16) bool {
	if metric != Infinity {
		var r [10]byte
		binary.BigEndian.PutUint64(r[2:], router)
		if !p.tlv(TypeRouterID, r[:]) {
			return false
		}
	}
	var b [10 + 16]byte
	b[0] = 2 // AE 2, IPv6.
	b[2] = bits
	binary.BigEndian.PutUint16(b[4:], interval)
	binary.BigEndian.PutUint16(b[6:], seqno)
	binary.BigEndian.PutUint16(b[8:], metric)
	n := (int(bits) + 7) / 8
	copy(b[10:], prefix[:n])
	return p.tlv(TypeUpdate, b[:10+n])
}

// Request adds a wildcard route Request.
func (p *Packet) WildcardRequest() bool {
	return p.tlv(TypeRequest, []byte{0, 0})
}

// Decode calls visit for each Hello, IHU, Ack, Ack Request, Update, Request
// and Seqno Request in packet. Malformed TLVs are skipped, as wb_decode does.
func Decode(packet []byte, visit func(*Message)) error {
	if len(packet) < 4 || packet[0] != magic || packet[1] != version {
		return ErrInvalid
	}
	body := int(binary.BigEndian.Uint16(packet[2:]))
	if body > len(packet)-4 {
		return ErrInvalid
	}
	end := 4 + body
	for pos := 4; pos < end; {
		t := packet[pos]
		pos++
		if t == TypePad1 {
			continue
		}
		if pos >= end || int(packet[pos]) > end-pos-1 {
			return ErrInvalid
		}
		pos += 1 + int(packet[pos])
	}
	var router uint64
	for pos := 4; pos < end; {
		t := packet[pos]
		pos++
		if t == TypePad1 {
			continue
		}
		n := int(packet[pos])
		b := packet[pos+1 : pos+1+n]
		pos += 1 + n
		m := Message{Type: t}
		switch t {
		case TypeHello, TypeAckRequest:
			if n < 6 {
				continue
			}
			m.Unicast = b[0]&0x80 != 0
			m.Seqno = binary.BigEndian.Uint16(b[2:])
			m.Opaque = m.Seqno
			m.Interval = binary.BigEndian.Uint16(b[4:])
			if t == TypeAckRequest && m.Interval == 0 {
				continue
			}
		case TypeAck:
			if n < 2 {
				continue
			}
			m.Opaque = binary.BigEndian.Uint16(b)
		case TypeIHU:
			if n < 6 {
				continue
			}
			m.Metric = binary.BigEndian.Uint16(b[2:])
			m.Interval = binary.BigEndian.Uint16(b[4:])
			if m.Interval == 0 {
				continue
			}
		case TypeRouterID:
			if n >= 10 {
				router = binary.BigEndian.Uint64(b[2:])
			}
			continue
		case TypeUpdate:
			if n < 10 {
				continue
			}
			m.Interval = binary.BigEndian.Uint16(b[4:])
			m.Seqno = binary.BigEndian.Uint16(b[6:])
			m.Metric = binary.BigEndian.Uint16(b[8:])
			m.Router = router
			if b[0] == 0 {
				m.Wildcard = true
			} else if !readPrefix(&m, b[0], b[2], b[10:]) || b[3] != 0 {
				continue // Omitted bytes are not used by Wendy peers.
			}
			if m.Interval == 0 {
				continue
			}
		case TypeRequest, TypeSeqRequest:
			base := 2
			if t == TypeSeqRequest {
				base = 14
			}
			if n < base {
				continue
			}
			if b[0] == 0 {
				if t != TypeRequest || b[1] != 0 {
					continue
				}
				m.Wildcard = true
			} else if !readPrefix(&m, b[0], b[1], b[base:]) {
				continue
			}
			if t == TypeSeqRequest {
				m.Seqno = binary.BigEndian.Uint16(b[2:])
				m.Hops = b[4]
				m.Router = binary.BigEndian.Uint64(b[6:])
				if m.Hops == 0 || m.Router == 0 || m.Router == ^uint64(0) {
					continue
				}
			}
		default:
			continue
		}
		visit(&m)
	}
	return nil
}

// readPrefix reads an AE 1 or AE 2 prefix. Link local AE 3 is not used for routes here.
func readPrefix(m *Message, ae, bits uint8, b []byte) bool {
	limit := uint8(128)
	if ae == 1 {
		limit = 32
	} else if ae != 2 {
		return false
	}
	n := (int(bits) + 7) / 8
	if bits > limit || n > len(b) {
		return false
	}
	m.Family, m.Bits = 6, bits
	if ae == 1 {
		m.Family = 4
	}
	copy(m.Prefix[:], b[:n])
	return true
}
