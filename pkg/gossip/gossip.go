// Package gossip moves artifacts over one link, as wg_receive and wg_poll in wendy-lite
// components/wendy_net_gossip/src/gossip.c do. It checks digests, not signatures.
package gossip

import (
	"errors"

	"github.com/hybridgroup/tink/pkg/control"
	"github.com/soypat/lcrypto/sha256"
)

const (
	IdleMS = 30000 // WG_IDLE_MS
	// MaxObjects is how many local artifacts a Session serves.
	MaxObjects = 4
	// MaxPending is how many announced artifacts wait to be fetched.
	MaxPending = 8
	maxUploads = 4
)

var (
	ErrDigest = errors.New("gossip: body does not match its digest")
	ErrFull   = errors.New("gossip: no room for another object")
)

// Identify returns SHA-256 of "wendy-mesh-artifact/1\0", type, u32BE length and data,
// as wn_gossip_identify and WendyOS netgossip.Identify compute it.
func Identify(typ uint8, data []byte) [32]byte {
	var d sha256.Digest
	var hdr [5]byte
	return identify(&d, &hdr, typ, data)
}

var artifactDomain = []byte("wendy-mesh-artifact/1\x00")

func identify(d *sha256.Digest, hdr *[5]byte, typ uint8, data []byte) (sum [32]byte) {
	d.Init()
	d.Write(artifactDomain)
	n := len(data)
	*hdr = [5]byte{typ, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	d.Write(hdr[:])
	d.Write(data)
	d.Sum(sum[:0])
	return sum
}

// Emit sends one gossip message. It must not keep g.
type Emit func(g *control.Gossip) error

// Complete receives a digest checked body. data is valid only during the call.
type Complete func(typ uint8, digest [32]byte, data []byte)

type object struct {
	digest  [32]byte
	data    []byte
	expires uint64
	used    bool
}

type upload struct {
	obj     *object
	request uint64
	offset  int
	used    bool
}

type fetch struct {
	digest   [32]byte
	request  uint64
	buf      []byte
	size     int
	progress uint64
	used     bool
}

// Session is the gossip state of one link. Type is the artifact type it carries.
type Session struct {
	Type    uint8
	objects [MaxObjects]object
	uploads [maxUploads]upload
	pending [MaxPending]fetch
	// next upload slot to serve, so uploads take turns one chunk at a time.
	turn        int
	nextRequest uint64
	// Hash state lives here so digests do not allocate.
	digest sha256.Digest
	hdr    [5]byte
}

// Offer stores data to serve until expiresMS and returns its digest for Have.
// When the Session is full it replaces the object that expires first.
func (s *Session) Offer(data []byte, expiresMS uint64) [32]byte {
	id := identify(&s.digest, &s.hdr, s.Type, data)
	slot := &s.objects[0]
	for i := range s.objects {
		o := &s.objects[i]
		if o.used && o.digest == id {
			o.expires = max(o.expires, expiresMS)
			return id
		}
		if !o.used || o.expires < slot.expires {
			slot = o
		}
	}
	*slot = object{digest: id, data: append(slot.data[:0], data...), expires: expiresMS, used: true}
	return id
}

// Forget stops serving digest. Transfers in progress end with UNAVAILABLE.
func (s *Session) Forget(digest [32]byte) {
	for i := range s.objects {
		if s.objects[i].used && s.objects[i].digest == digest {
			s.objects[i].used = false
		}
	}
}

// Have announces digest to the peer.
func (s *Session) Have(emit Emit, digest [32]byte) error {
	return emit(&control.Gossip{Op: control.OpHave, Type: s.Type, Digest: digest})
}

// Gone withdraws an earlier Have.
func (s *Session) Gone(emit Emit, digest [32]byte) error {
	s.Forget(digest)
	return emit(&control.Gossip{Op: control.OpGone, Type: s.Type, Digest: digest})
}

func (s *Session) find(digest [32]byte, now uint64) *object {
	for i := range s.objects {
		o := &s.objects[i]
		if o.used && o.digest == digest && o.expires > now {
			return o
		}
	}
	return nil
}

func (s *Session) findFetch(digest [32]byte) *fetch {
	for i := range s.pending {
		if f := &s.pending[i]; f.used && f.digest == digest {
			return f
		}
	}
	return nil
}

// Receive handles one validated message from the peer at nowMS.
func (s *Session) Receive(g *control.Gossip, nowMS uint64, emit Emit, complete Complete) error {
	if g.Type != s.Type {
		return control.ErrInvalid
	}
	switch g.Op {
	case control.OpHave:
		if s.find(g.Digest, nowMS) != nil || s.findFetch(g.Digest) != nil {
			return nil
		}
		for i := range s.pending {
			if f := &s.pending[i]; !f.used {
				*f = fetch{digest: g.Digest, used: true, buf: f.buf[:0]}
				return s.claim(f, nowMS, emit)
			}
		}
		return nil // Hints beyond MaxPending are dropped, as Lite does when full.
	case control.OpGone:
		if f := s.findFetch(g.Digest); f != nil {
			f.used = false
		}
		return nil
	case control.OpWant:
		for i := range s.uploads {
			if u := &s.uploads[i]; u.used && u.request == g.Request {
				return nil
			}
		}
		o := s.find(g.Digest, nowMS)
		if o != nil {
			for i := range s.uploads {
				if u := &s.uploads[i]; !u.used {
					*u = upload{obj: o, request: g.Request, used: true}
					return nil
				}
			}
		}
		return emit(&control.Gossip{Op: control.OpUnavailable, Type: s.Type, Digest: g.Digest, Request: g.Request})
	}
	f := s.findFetch(g.Digest)
	if f == nil || f.request != g.Request {
		return nil
	}
	if g.Op == control.OpUnavailable {
		f.used = false
		return nil
	}
	// DATA must be contiguous and keep the same total.
	if int(g.Offset) != f.size || (f.size > 0 && len(f.buf) != int(g.Total)) {
		f.used = false
		return control.ErrInvalid
	}
	if f.size == 0 {
		if cap(f.buf) < int(g.Total) {
			f.buf = make([]byte, g.Total)
		}
		f.buf = f.buf[:g.Total]
	}
	f.size += copy(f.buf[f.size:], g.Data)
	f.progress = nowMS
	if f.size < len(f.buf) {
		return nil
	}
	f.used = false
	if identify(&s.digest, &s.hdr, s.Type, f.buf) != f.digest {
		return ErrDigest
	}
	complete(s.Type, f.digest, f.buf)
	return nil
}

func (s *Session) claim(f *fetch, now uint64, emit Emit) error {
	s.nextRequest++
	f.request = s.nextRequest
	f.progress = now
	return emit(&control.Gossip{Op: control.OpWant, Type: s.Type, Digest: f.digest, Request: f.request})
}

// Poll sends at most one DATA chunk or UNAVAILABLE and drops fetches idle
// for IdleMS. Call it regularly, for example every routing tick.
func (s *Session) Poll(nowMS uint64, emit Emit) error {
	for i := range s.pending {
		if f := &s.pending[i]; f.used && nowMS-f.progress >= IdleMS {
			f.used = false
		}
	}
	for range s.uploads {
		u := &s.uploads[s.turn]
		s.turn = (s.turn + 1) % len(s.uploads)
		if !u.used {
			continue
		}
		o := u.obj
		if !o.used || o.expires <= nowMS {
			u.used = false
			return emit(&control.Gossip{Op: control.OpUnavailable, Type: s.Type, Digest: o.digest, Request: u.request})
		}
		n := min(len(o.data)-u.offset, control.Chunk)
		g := control.Gossip{Op: control.OpData, Type: s.Type, Digest: o.digest, Request: u.request,
			Offset: uint32(u.offset), Total: uint32(len(o.data)), Data: o.data[u.offset : u.offset+n]}
		if err := emit(&g); err != nil {
			return err
		}
		u.offset += n
		if u.offset == len(o.data) {
			u.used = false
		}
		return nil
	}
	return nil
}

// Busy reports whether uploads or fetches are in progress.
func (s *Session) Busy() bool {
	for i := range s.uploads {
		if s.uploads[i].used {
			return true
		}
	}
	for i := range s.pending {
		if s.pending[i].used && s.pending[i].size > 0 {
			return true
		}
	}
	return false
}
