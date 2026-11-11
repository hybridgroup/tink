// Package mdns finds Wendy Net routers with a legacy unicast query, RFC 6762 section 6.7.
// It filters results as discovery_results in wendy-lite components/wendy_net_peer/src/peer.c.
package mdns

import (
	"encoding/binary"
	"errors"

	"github.com/hybridgroup/tink/pkg/addr"
)

const (
	Service = "_wendy-net._tcp.local"
	Port    = 5353
	// QueryMax is the size of a query from WriteQuery.
	QueryMax = 64
	typeA    = 1
	typePTR  = 12
	typeTXT  = 16
	typeSRV  = 33
	classIN  = 1
	// unicastResponse is the QU bit of RFC 6762 section 5.4.
	unicastResponse = 0x8000
	maxRecords      = 32
	maxServices     = 8
)

// Group is the IPv4 mDNS group, 224.0.0.251.
var Group = [4]byte{224, 0, 0, 251}

var ErrInvalid = errors.New("mdns: invalid message")

// WriteQuery writes a PTR query for Service with the QU bit set.
func WriteQuery(buf []byte, id uint16) []byte {
	b := buf[:0]
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) // flags, 1 question.
	b = appendName(b, Service)
	b = binary.BigEndian.AppendUint16(b, typePTR)
	b = binary.BigEndian.AppendUint16(b, unicastResponse|classIN)
	return b
}

func appendName(b []byte, name string) []byte {
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, name[start:i]...)
			start = i + 1
		}
	}
	return append(b, 0)
}

// Instance is one advertised router.
type Instance struct {
	Name      string // Service instance name.
	Host      string
	Port      uint16
	IPv4      [4]byte
	Version   string
	Protocol  string
	Principal string
	Role      string
	txtBad    bool
}

// Candidate is a router to dial.
type Candidate struct {
	Device addr.UUID
	IPv4   [4]byte
	Port   uint16
}

type record struct {
	name, target string
	typ          uint16
	port         uint16
	ipv4         [4]byte
	txt          []byte
	ttl          uint32
}

// Parse reads a response and returns the advertised instances of Service.
func Parse(msg []byte) ([]Instance, error) {
	if len(msg) < 12 || msg[2]&0x80 == 0 {
		return nil, ErrInvalid // Not a response.
	}
	qd := int(binary.BigEndian.Uint16(msg[4:]))
	rr := int(binary.BigEndian.Uint16(msg[6:])) + int(binary.BigEndian.Uint16(msg[8:])) + int(binary.BigEndian.Uint16(msg[10:]))
	off := 12
	for range qd {
		_, n, err := readName(msg, off)
		if err != nil || n+4 > len(msg) {
			return nil, ErrInvalid
		}
		off = n + 4
	}
	var records []record
	for range min(rr, maxRecords) {
		name, n, err := readName(msg, off)
		if err != nil || n+10 > len(msg) {
			return nil, ErrInvalid
		}
		typ := binary.BigEndian.Uint16(msg[n:])
		class := binary.BigEndian.Uint16(msg[n+2:]) &^ 0x8000 // Cache flush bit.
		ttl := binary.BigEndian.Uint32(msg[n+4:])
		size := int(binary.BigEndian.Uint16(msg[n+8:]))
		data := n + 10
		if data+size > len(msg) {
			return nil, ErrInvalid
		}
		off = data + size
		if class != classIN {
			continue
		}
		r := record{name: name, typ: typ, ttl: ttl}
		switch typ {
		case typePTR:
			if r.target, _, err = readName(msg, data); err != nil {
				return nil, ErrInvalid
			}
		case typeSRV:
			if size < 7 {
				return nil, ErrInvalid
			}
			r.port = binary.BigEndian.Uint16(msg[data+4:])
			if r.target, _, err = readName(msg, data+6); err != nil {
				return nil, ErrInvalid
			}
		case typeTXT:
			r.txt = msg[data : data+size]
		case typeA:
			if size != 4 {
				return nil, ErrInvalid
			}
			copy(r.ipv4[:], msg[data:])
		default:
			continue
		}
		records = append(records, r)
	}
	var out []Instance
	for _, p := range records {
		if p.typ != typePTR || !equalFold(p.name, Service) || p.ttl == 0 || len(out) == maxServices {
			continue
		}
		in := Instance{Name: p.target}
		for _, r := range records {
			if !equalFold(r.name, p.target) {
				continue
			}
			switch r.typ {
			case typeSRV:
				in.Host, in.Port = r.target, r.port
			case typeTXT:
				in.parseTXT(r.txt)
			}
		}
		for _, r := range records {
			if r.typ == typeA && in.Host != "" && equalFold(r.name, in.Host) {
				in.IPv4 = r.ipv4
				break
			}
		}
		out = append(out, in)
	}
	return out, nil
}

// parseTXT reads key=value strings. A repeated wanted key marks the instance invalid, as Lite does.
func (in *Instance) parseTXT(b []byte) {
	for len(b) > 0 {
		n := int(b[0])
		if 1+n > len(b) {
			in.txtBad = true
			return
		}
		kv := string(b[1 : 1+n])
		b = b[1+n:]
		for i := 0; i < len(kv); i++ {
			if kv[i] != '=' {
				continue
			}
			key, value := kv[:i], kv[i+1:]
			var dst *string
			switch key {
			case "version":
				dst = &in.Version
			case "protocol":
				dst = &in.Protocol
			case "principal":
				dst = &in.Principal
			case "role":
				dst = &in.Role
			}
			if dst != nil {
				in.txtBad = in.txtBad || *dst != ""
				*dst = value
			}
			break
		}
	}
}

// Candidate checks in as Lite does and returns the router to dial.
func (in *Instance) Candidate(tenant, self addr.UUID) (Candidate, bool) {
	if in.txtBad || in.Port == 0 || in.Version != "1" || in.Protocol != "tls-v1" ||
		(in.Role != "router" && in.Role != "embedded-router") {
		return Candidate{}, false
	}
	device, err := addr.PrincipalDevice(in.Principal, tenant)
	if err != nil || device == self {
		return Candidate{}, false
	}
	ip := in.IPv4
	if ip[0] == 0 || ip[0] == 127 || ip[0] >= 224 || (ip[0] == 169 && ip[1] == 254) {
		return Candidate{}, false
	}
	return Candidate{Device: device, IPv4: ip, Port: in.Port}, true
}

// readName reads a possibly compressed name at off. It returns the dotted
// name and the offset after it in the record.
func readName(msg []byte, off int) (string, int, error) {
	var name []byte
	end := -1
	for jumps := 0; ; {
		if off >= len(msg) {
			return "", 0, ErrInvalid
		}
		n := int(msg[off])
		switch {
		case n == 0:
			if end < 0 {
				end = off + 1
			}
			return string(name), end, nil
		case n&0xc0 == 0xc0:
			if off+1 >= len(msg) || jumps > 16 {
				return "", 0, ErrInvalid
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3fff)
			jumps++
		case n&0xc0 != 0:
			return "", 0, ErrInvalid
		default:
			if off+1+n > len(msg) || len(name)+n > 255 {
				return "", 0, ErrInvalid
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, msg[off+1:off+1+n]...)
			off += 1 + n
		}
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
