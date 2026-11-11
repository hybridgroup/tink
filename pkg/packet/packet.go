// Package packet splits mesh IPv6 packets into at most two fragment datagrams and joins
// them, as wendy-lite components/wendy_net_peer/src/packet.c does.
package packet

import (
	"encoding/binary"
	"errors"
)

const (
	MTU          = 1320 // WN_MTU
	DatagramMax  = 1100 // WN_DATAGRAM_MAX
	FragmentData = DatagramMax - fragmentHdr
	KindFragment = 1
	KindBabel    = 2
	fragmentHdr  = 9
	reassemblyUS = 2_000_000
)

var ErrInvalid = errors.New("packet: invalid IPv6 packet or fragment")

func validIPv6(p []byte) bool {
	return len(p) >= 40 && len(p) <= MTU && p[0]>>4 == 6 && int(binary.BigEndian.Uint16(p[4:])) == len(p)-40
}

// Fragment writes the fragment of p at offset into out and returns its length.
// Call it with offset 0, and with FragmentData when len(p) > FragmentData.
func Fragment(out *[DatagramMax]byte, p []byte, id uint32, offset int) (int, error) {
	if !validIPv6(p) || (offset != 0 && offset != FragmentData) || offset >= len(p) {
		return 0, ErrInvalid
	}
	count := min(len(p)-offset, FragmentData)
	out[0] = KindFragment
	binary.BigEndian.PutUint32(out[1:], id)
	binary.BigEndian.PutUint16(out[5:], uint16(len(p)))
	binary.BigEndian.PutUint16(out[7:], uint16(offset))
	copy(out[fragmentHdr:], p[offset:offset+count])
	return fragmentHdr + count, nil
}

// Assembler joins the one or two fragments of a packet.
type Assembler struct {
	buf      [MTU]byte
	id       uint32
	total    int
	received int
	parts    uint8
	deadline int64
}

// Add returns the complete packet, valid until the next call, or nil while
// incomplete. Datagrams of other kinds return nil and leave a partial packet alone.
func (s *Assembler) Add(d []byte, nowUS int64) ([]byte, error) {
	if len(d) == 0 || len(d) > DatagramMax {
		return nil, ErrInvalid
	} else if d[0] != KindFragment {
		return nil, nil
	} else if len(d) < 10 {
		return nil, ErrInvalid
	}
	id := binary.BigEndian.Uint32(d[1:])
	total := int(binary.BigEndian.Uint16(d[5:]))
	offset := int(binary.BigEndian.Uint16(d[7:]))
	count := len(d) - fragmentHdr
	if total < 40 || total > MTU || (offset != 0 && offset != FragmentData) || offset >= total ||
		count != min(total-offset, FragmentData) {
		return nil, ErrInvalid
	}
	if s.parts == 0 || nowUS >= s.deadline || s.id != id {
		*s = Assembler{id: id, total: total, deadline: nowUS + reassemblyUS}
	}
	part := uint8(1)
	if offset != 0 {
		part = 2
	}
	if s.total != total || s.parts&part != 0 {
		s.parts = 0
		return nil, ErrInvalid
	}
	copy(s.buf[offset:], d[fragmentHdr:])
	s.received += count
	s.parts |= part
	if s.received != total {
		return nil, nil
	}
	s.parts = 0
	p := s.buf[:total]
	if !validIPv6(p) {
		return nil, ErrInvalid
	}
	return p, nil
}
