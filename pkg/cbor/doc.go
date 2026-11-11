package cbor

import "errors"

const (
	// MaxTokens matches WN_TOKENS.
	MaxTokens  = 128
	maxDepth   = 16
	maxMapLen  = 64
	maxListLen = 1024
)

var (
	ErrParse    = errors.New("cbor: invalid or non canonical document")
	ErrType     = errors.New("cbor: wrong type")
	ErrNotFound = errors.New("cbor: member not found")
)

// Kind is the type of a token.
type Kind byte

const (
	KindInvalid Kind = iota
	KindUint
	KindNeg
	KindBytes
	KindText
	KindArray
	KindMap
	KindFalse
	KindTrue
	KindNull
)

type token struct {
	start, end uint32
	next       uint16 // Index after this token's subtree.
	kind       Kind
	header     uint8
}

// Doc is a parsed document. Tokens borrow the input bytes, so Doc does not
// allocate. Token 0 is the root.
type Doc struct {
	data   []byte
	count  int
	pos    int // Parse cursor, kept here so Parse does not allocate.
	tokens [MaxTokens]token
}

// Parse parses data, which must hold exactly one value.
func (d *Doc) Parse(data []byte) error {
	d.data, d.count = data, 0
	if len(data) == 0 {
		return ErrParse
	}
	d.pos = 0
	if _, err := d.value(&d.pos, 0); err != nil {
		d.count = 0
		return err
	} else if d.pos != len(data) {
		d.count = 0
		return ErrParse
	}
	return nil
}

// argument reads a minimally encoded head, as Lite's argument() requires.
func argument(data []byte, at *int) (major byte, header uint8, v uint64, err error) {
	if *at >= len(data) {
		return 0, 0, 0, ErrParse
	}
	first := data[*at]
	major, small := first>>5, first&31
	if small < 24 {
		*at++
		return major, 1, uint64(small), nil
	} else if small > 27 {
		return 0, 0, 0, ErrParse
	}
	n := 1 << (small - 24)
	if n > len(data)-*at-1 {
		return 0, 0, 0, ErrParse
	}
	for i := range n {
		v = v<<8 | uint64(data[*at+1+i])
	}
	if v < 24 || (n > 1 && v < 1<<(8*(n/2))) {
		return 0, 0, 0, ErrParse
	}
	*at += 1 + n
	return major, uint8(1 + n), v, nil
}

func (d *Doc) value(at *int, depth int) (int, error) {
	if depth > maxDepth || d.count == MaxTokens {
		return -1, ErrParse
	}
	idx := d.count
	d.count++
	t := &d.tokens[idx]
	t.start = uint32(*at)
	major, header, n, err := argument(d.data, at)
	if err != nil {
		return -1, err
	}
	t.header = header
	switch major {
	case 0:
		t.kind = KindUint
	case 1:
		t.kind = KindNeg
	case 2, 3:
		if n > uint64(len(d.data)-*at) {
			return -1, ErrParse
		}
		t.kind = KindBytes
		if major == 3 {
			t.kind = KindText
			if !validUTF8(d.data[*at : *at+int(n)]) {
				return -1, ErrParse
			}
		}
		*at += int(n)
	case 4, 5:
		if n > maxListLen || (major == 5 && n > maxMapLen) {
			return -1, ErrParse
		}
		t.kind = KindArray
		if major == 5 {
			t.kind = KindMap
		}
		for range n {
			if major == 5 {
				key, err := d.value(at, depth+1)
				if err != nil {
					return -1, err
				} else if d.tokens[key].kind != KindText {
					return -1, ErrParse
				}
				for old := idx + 1; old < key; old = int(d.tokens[old+1].next) {
					if string(d.textOf(old)) == string(d.textOf(key)) {
						return -1, ErrParse
					}
				}
			}
			if _, err := d.value(at, depth+1); err != nil {
				return -1, err
			}
		}
	case 7:
		switch n {
		case 20:
			t.kind = KindFalse
		case 21:
			t.kind = KindTrue
		case 22:
			t.kind = KindNull
		default:
			return -1, ErrParse
		}
	default:
		return -1, ErrParse
	}
	t.end = uint32(*at)
	t.next = uint16(d.count)
	return idx, nil
}

func (d *Doc) textOf(i int) []byte {
	t := &d.tokens[i]
	return d.data[int(t.start)+int(t.header) : t.end]
}

func (d *Doc) tok(i int) *token {
	if i < 0 || i >= d.count {
		return nil
	}
	return &d.tokens[i]
}

// Kind returns the kind of token i, or KindInvalid.
func (d *Doc) Kind(i int) Kind {
	if t := d.tok(i); t != nil {
		return t.kind
	}
	return KindInvalid
}

// Member returns the value token of field name in map obj. name is
// translated with KeyName, as wn_doc_member does.
func (d *Doc) Member(obj int, name string) int {
	t := d.tok(obj)
	if t == nil || t.kind != KindMap {
		return -1
	}
	key := KeyName(name)
	for i := obj + 1; i < int(t.next); i = int(d.tokens[i+1].next) {
		if string(d.textOf(i)) == key {
			return i + 1
		}
	}
	return -1
}

// Fields reports whether every key of map obj is one of names.
func (d *Doc) Fields(obj int, names ...string) bool {
	t := d.tok(obj)
	if t == nil || t.kind != KindMap {
		return false
	}
	for i := obj + 1; i < int(t.next); i = int(d.tokens[i+1].next) {
		found := false
		for _, n := range names {
			found = found || string(d.textOf(i)) == KeyName(n)
		}
		if !found {
			return false
		}
	}
	return true
}

// Len returns the number of entries of a map or array token.
func (d *Doc) Len(i int) int {
	t := d.tok(i)
	if t == nil || (t.kind != KindMap && t.kind != KindArray) {
		return -1
	}
	at := int(t.start)
	_, _, n, _ := argument(d.data, &at)
	return int(n)
}

// Elem returns the token of element k of array arr.
func (d *Doc) Elem(arr, k int) int {
	t := d.tok(arr)
	if t == nil || t.kind != KindArray || k < 0 {
		return -1
	}
	i := arr + 1
	for ; k > 0 && i < int(t.next); k-- {
		i = int(d.tokens[i].next)
	}
	if i >= int(t.next) {
		return -1
	}
	return i
}

func (d *Doc) Uint(i int) (uint64, error) {
	t := d.tok(i)
	if t == nil || t.kind != KindUint {
		return 0, ErrType
	}
	at := int(t.start)
	_, _, v, err := argument(d.data, &at)
	return v, err
}

// Text returns a text token. It borrows the parsed data.
func (d *Doc) Text(i int) ([]byte, error) {
	t := d.tok(i)
	if t == nil || t.kind != KindText {
		return nil, ErrType
	}
	return d.textOf(i), nil
}

// Bytes returns a byte string token. It borrows the parsed data.
func (d *Doc) Bytes(i int) ([]byte, error) {
	t := d.tok(i)
	if t == nil || t.kind != KindBytes {
		return nil, ErrType
	}
	return d.textOf(i), nil
}

// Equal reports whether token i is the text s.
func (d *Doc) Equal(i int, s string) bool {
	b, err := d.Text(i)
	return err == nil && string(b) == s
}

// Raw returns the encoded bytes of token i and its subtree.
func (d *Doc) Raw(i int) []byte {
	t := d.tok(i)
	if t == nil {
		return nil
	}
	return d.data[t.start:t.end]
}

func validUTF8(b []byte) bool {
	for at := 0; at < len(b); {
		c := uint32(b[at])
		at++
		if c < 0x80 {
			continue
		}
		var rest int
		switch {
		case c >= 0xc2 && c <= 0xdf:
			rest, c = 1, c&0x1f
		case c >= 0xe0 && c <= 0xef:
			rest, c = 2, c&0x0f
		case c >= 0xf0 && c <= 0xf4:
			rest, c = 3, c&7
		default:
			return false
		}
		count := rest
		if rest > len(b)-at {
			return false
		}
		for ; rest > 0; rest-- {
			x := uint32(b[at])
			at++
			if x&0xc0 != 0x80 {
				return false
			}
			c = c<<6 | x&0x3f
		}
		if (count == 2 && c < 0x800) || (count == 3 && c < 0x10000) ||
			(c >= 0xd800 && c <= 0xdfff) || c > 0x10ffff {
			return false
		}
	}
	return true
}
