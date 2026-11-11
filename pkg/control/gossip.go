package control

import "github.com/hybridgroup/tink/pkg/cbor"

// Op is a gossip operation.
type Op uint8

const (
	OpHave Op = iota
	OpWant
	OpUnavailable
	OpData
	OpGone
)

var opNames = [...]string{"have", "want", "unavailable", "data", "gone"}

func (o Op) String() string {
	if int(o) < len(opNames) {
		return opNames[o]
	}
	return "unknown"
}

const (
	Chunk     = 1024      // WG_CHUNK
	ObjectMax = 40 * 1024 // WG_OBJECT_MAX
	// TypeManifest is the only artifact type Lite gossips today.
	TypeManifest = 1
)

// Gossip is one gossip message. Data borrows the decoded frame.
type Gossip struct {
	Op      Op
	Type    uint8
	Digest  [32]byte
	Request uint64
	Offset  uint32
	Total   uint32
	Data    []byte
}

// Validate applies the field rules of wg_validate in components/wendy_net_gossip/src/gossip.c.
func (g *Gossip) Validate() error {
	if g.Type != 1 && g.Type != 2 && g.Type != 3 {
		return ErrInvalid
	}
	switch g.Op {
	case OpHave, OpGone:
		if g.Request != 0 || g.Offset != 0 || g.Total != 0 || len(g.Data) != 0 {
			return ErrInvalid
		}
	case OpWant, OpUnavailable:
		if g.Request == 0 || g.Offset != 0 || g.Total != 0 || len(g.Data) != 0 {
			return ErrInvalid
		}
	case OpData:
		if g.Request == 0 || g.Total == 0 || g.Total > ObjectMax || g.Offset >= g.Total ||
			g.Offset%Chunk != 0 || len(g.Data) != int(min(g.Total-g.Offset, Chunk)) {
			return ErrInvalid
		}
	default:
		return ErrUnsupported
	}
	return nil
}

// WriteGossip writes a type 1 gossip message, as wn_gossip_write does.
func WriteGossip(w *cbor.Writer, g *Gossip) ([]byte, error) {
	if err := g.Validate(); err != nil || g.Type != TypeManifest {
		return nil, ErrInvalid
	}
	w.Map(2)
	w.Key("kind")
	w.Text("gossip")
	w.Key("gossip")
	w.Map(8)
	w.Key("v")
	w.Uint(1)
	w.Key("op")
	w.Text(g.Op.String())
	w.Key("data")
	w.Bytes(g.Data)
	w.Key("type")
	w.Uint(uint64(g.Type))
	w.Key("total")
	w.Uint(uint64(g.Total))
	w.Key("digest")
	w.Bytes(g.Digest[:])
	w.Key("offset")
	w.Uint(uint64(g.Offset))
	w.Key("request")
	w.Uint(g.Request)
	return w.Finish()
}

// ReadGossip decodes a gossip message. It returns ErrUnsupported for a
// future version, type or operation, which the caller should ignore.
func ReadGossip(d *cbor.Doc, g *Gossip) error {
	if !d.Equal(d.Member(0, "kind"), "gossip") {
		return ErrInvalid
	}
	m := d.Member(0, "gossip")
	if d.Kind(m) != cbor.KindMap {
		return ErrInvalid
	}
	v, err := d.Uint(d.Member(m, "v"))
	if err != nil {
		return ErrInvalid
	} else if v != 1 {
		return ErrUnsupported
	}
	typ, err := d.Uint(d.Member(m, "type"))
	if err != nil {
		return ErrInvalid
	} else if typ != TypeManifest {
		return ErrUnsupported
	}
	opTok := d.Member(m, "op")
	if op, err := d.Text(opTok); err != nil || len(op) == 0 {
		return ErrInvalid
	}
	*g = Gossip{Type: uint8(typ), Op: 255}
	for i, n := range opNames {
		if d.Equal(opTok, n) {
			g.Op = Op(i)
		}
	}
	if g.Op == 255 {
		return ErrUnsupported
	}
	var offset, total uint64
	if g.Request, err = optionalUint(d, m, "request"); err != nil {
		return err
	} else if offset, err = optionalUint(d, m, "offset"); err != nil || offset > 0xffffffff {
		return ErrInvalid
	} else if total, err = optionalUint(d, m, "total"); err != nil || total > 0xffffffff {
		return ErrInvalid
	}
	g.Offset, g.Total = uint32(offset), uint32(total)
	digest, err := d.Bytes(d.Member(m, "digest"))
	if err != nil || len(digest) != 32 {
		return ErrInvalid
	}
	copy(g.Digest[:], digest)
	if t := d.Member(m, "data"); t >= 0 {
		if g.Data, err = d.Bytes(t); err != nil {
			return ErrInvalid
		}
	}
	return g.Validate()
}

func optionalUint(d *cbor.Doc, obj int, name string) (uint64, error) {
	t := d.Member(obj, name)
	if t < 0 {
		return 0, nil
	}
	v, err := d.Uint(t)
	if err != nil {
		return 0, ErrInvalid
	}
	return v, nil
}
