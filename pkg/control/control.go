// Package control encodes Wendy Net control messages, as wendy-lite
// components/wendy_net_peer/src/control.c and protocol.c do.
package control

import (
	"errors"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/cbor"
)

const (
	MTU         = 1320 // WN_MTU
	DatagramMax = 1100 // WN_DATAGRAM_MAX
	ControlMax  = 2048 // WN_CONTROL_MAX
	Version     = 1
)

var (
	ErrInvalid = errors.New("control: invalid message")
	// ErrUnsupported is a well formed message of a future version, type or operation.
	ErrUnsupported = errors.New("control: unsupported message")
)

// Kind returns the kind field of a control message.
func Kind(d *cbor.Doc) string {
	b, err := d.Text(d.Member(0, "kind"))
	if err != nil {
		return ""
	}
	return string(b)
}

// WriteHello writes the router hello sent after the TLS handshake.
func WriteHello(w *cbor.Writer, self, peer addr.UUID) ([]byte, error) {
	if self == peer {
		return nil, ErrInvalid
	}
	w.Map(2)
	w.Key("kind")
	w.Text("hello")
	w.Key("hello")
	w.Map(5)
	w.Key("mtu")
	w.Uint(MTU)
	w.Key("peer")
	w.Text(peer.String())
	w.Key("device")
	w.Text(self.String())
	w.Key("version")
	w.Uint(Version)
	w.Key("datagram")
	w.Uint(DatagramMax)
	return w.Finish()
}

// CheckHello checks a hello from peer to self, as wn_router_hello_check does.
// Unknown additional fields are allowed.
func CheckHello(d *cbor.Doc, self, peer addr.UUID) error {
	if self == peer || Kind(d) != "hello" {
		return ErrInvalid
	}
	h := d.Member(0, "hello")
	if d.Kind(h) != cbor.KindMap {
		return ErrInvalid
	}
	for _, f := range [...]struct {
		name string
		want uint64
	}{{"version", Version}, {"mtu", MTU}, {"datagram", DatagramMax}} {
		if v, err := d.Uint(d.Member(h, f.name)); err != nil || v != f.want {
			return ErrInvalid
		}
	}
	if !d.Equal(d.Member(h, "device"), peer.String()) || !d.Equal(d.Member(h, "peer"), self.String()) {
		return ErrInvalid
	}
	if role := d.Member(h, "role"); role >= 0 && !d.Equal(role, "") && !d.Equal(role, "router") {
		return ErrInvalid
	}
	return nil
}

func writePrincipal(w *cbor.Writer, kind, principal string) ([]byte, error) {
	w.Map(2)
	w.Key("kind")
	w.Text(kind)
	w.Key("principal")
	w.Text(principal)
	return w.Finish()
}

func WriteIdentityRequest(w *cbor.Writer, principal string) ([]byte, error) {
	return writePrincipal(w, "identity-request", principal)
}

func WriteManifestRequest(w *cbor.Writer, principal string) ([]byte, error) {
	return writePrincipal(w, "manifest-request", principal)
}

// WriteMissing writes manifest-missing or identity-missing.
func WriteMissing(w *cbor.Writer, principal string, manifest bool) ([]byte, error) {
	if manifest {
		return writePrincipal(w, "manifest-missing", principal)
	}
	return writePrincipal(w, "identity-missing", principal)
}
