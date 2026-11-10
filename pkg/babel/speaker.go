package babel

// Timing used by Lite, router.c wnr_init and engine.c.
const (
	HelloMS  = 4000
	IHUMS    = 2 * HelloMS
	UpdateMS = 16000
	// LANCost is WNR_LAN_COST.
	LANCost = 128
	// hold is how long a Hello stays valid, 3.5 times its interval.
	holdNum, holdDen = 7, 2
)

// Speaker is the Babel state of a leaf on its one link.
type Speaker struct {
	// Router is this node's router id, the routerId in its signed manifest.
	Router uint64
	// Prefix is the device address, announced as a /128.
	Prefix [16]byte
	// Seqno is announced with the route. It must match the signed manifest.
	Seqno uint16
	// Cost is the rxcost sent in IHU, LANCost if zero.
	Cost uint16
	// SeqnoWanted is set when the neighbour asks for a newer seqno. The
	// caller signs a manifest with Seqno+1, sets Seqno and clears it.
	SeqnoWanted bool

	helloSeq    uint16
	nextHello   int64
	nextIHU     int64
	nextUpdate  int64
	helloUntil  int64
	ihuUntil    int64
	ihuCost     uint16
	updateNow   bool
	pendingAcks [4]uint16
	nAcks       int
}

func (s *Speaker) cost() uint16 {
	if s.Cost == 0 {
		return LANCost
	}
	return s.Cost
}

// Receive handles a Babel packet from the neighbour at nowMS.
func (s *Speaker) Receive(packet []byte, nowMS int64) error {
	return Decode(packet, func(m *Message) {
		switch m.Type {
		case TypeHello:
			s.helloUntil = nowMS + int64(m.Interval)*10*holdNum/holdDen
		case TypeIHU:
			s.ihuUntil = nowMS + int64(m.Interval)*10*holdNum/holdDen
			s.ihuCost = m.Metric
		case TypeAckRequest:
			if s.nAcks < len(s.pendingAcks) {
				s.pendingAcks[s.nAcks] = m.Opaque
				s.nAcks++
			}
		case TypeRequest:
			if m.Wildcard || s.ours(m) {
				s.updateNow = true
			}
		case TypeSeqRequest:
			if s.ours(m) {
				s.SeqnoWanted = s.SeqnoWanted || seqnoNewer(m.Seqno, s.Seqno)
				s.updateNow = true
			}
		}
	})
}

func (s *Speaker) ours(m *Message) bool {
	return m.Family == 6 && m.Bits == 128 && m.Prefix == s.Prefix
}

// seqnoNewer compares modulo 2^16, RFC 8966 3.2.1.
func seqnoNewer(a, b uint16) bool { return a != b && a-b < 0x8000 }

// Up reports whether the neighbour is heard and hears us with a finite cost.
func (s *Speaker) Up(nowMS int64) bool {
	return s.helloUntil > nowMS && s.ihuUntil > nowMS && s.ihuCost != Infinity
}

// Poll fills p with what is due at nowMS. Send p when it is not empty.
func (s *Speaker) Poll(p *Packet, nowMS int64) {
	p.Reset()
	for i := range s.nAcks {
		p.Ack(s.pendingAcks[i])
	}
	s.nAcks = 0
	if nowMS >= s.nextHello {
		p.Hello(s.helloSeq, HelloMS/10)
		s.helloSeq++
		s.nextHello = nowMS + HelloMS
	}
	if nowMS >= s.nextIHU {
		rx := s.cost()
		if s.helloUntil <= nowMS {
			rx = Infinity
		}
		p.IHU(rx, IHUMS/10)
		s.nextIHU = nowMS + IHUMS
	}
	if s.updateNow || nowMS >= s.nextUpdate {
		p.Update(s.Router, s.Prefix, 128, s.Seqno, 0, UpdateMS/10)
		s.updateNow = false
		s.nextUpdate = nowMS + UpdateMS
	}
}

// Announce sends the route at the next Poll, for example after a new seqno.
func (s *Speaker) Announce() { s.updateNow = true }
