// Package manifest writes, signs and reads version 4 device manifests, as wendy-lite
// components/wendy_net_peer/src/protocol.c and wendy_pki/src/wendy_pki_mesh_crypto.c do.
package manifest

import (
	"errors"
	"strconv"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/cbor"
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/sha256"
)

const (
	Version     = 4
	BodyMax     = 32768 // WN_MANIFEST_BODY_MAX
	MaxLifetime = 900000
	// SignatureMax is the largest P-256 DER signature accepted, as in mesh_verify_key.
	SignatureMax = 80
	// WireMax is WN_MANIFEST_WIRE_MAX for P-256 signatures.
	WireMax = BodyMax + 3309 + 136
	// schemeECDSAP256SHA256 is RFC 8446 ecdsa_secp256r1_sha256.
	schemeECDSAP256SHA256 = 0x0403
)

// domain includes its NUL, as sizeof domain does in wendy_pki_mesh_crypto.c.
const domain = "wendy-local-mesh/manifest/4\x00"

var (
	ErrInvalid   = errors.New("manifest: invalid manifest")
	ErrSignature = errors.New("manifest: bad signature")
)

// Body is the signed manifest content of a device.
type Body struct {
	Device   addr.UUID
	RouterID uint64
	Seqno    uint16
	Revision uint64
	// Issued and Expires are Unix milliseconds.
	Issued, Expires int64
	AgentPort       uint16
	AppPort         uint16 // 0 when there is no app endpoint.
	Name            string // esp32-<first 8 of device> when empty.
	Sensors         bool
	// Services is a CBOR array written as is. An empty array when nil.
	Services []byte
}

// Write encodes b as wn_manifest_services_write does.
func (b *Body) Write(w *cbor.Writer) ([]byte, error) {
	if b.Revision == 0 || b.RouterID == 0 || b.RouterID == ^uint64(0) || b.Issued <= 0 ||
		b.Expires <= b.Issued || b.Expires-b.Issued > MaxLifetime || b.AgentPort == 0 || len(b.Name) > 255 {
		return nil, ErrInvalid
	}
	device := b.Device.String()
	name := b.Name
	if name == "" {
		name = "esp32-" + device[:8]
	}
	w.Map(13)
	w.Key("agentPort")
	w.Uint(uint64(b.AgentPort))
	w.Key("revision")
	w.Uint(b.Revision)
	w.Key("agentTransport")
	w.Text("mtls-v1")
	w.Key("appEndpoints")
	if b.AppPort != 0 {
		w.Array(1)
		w.Map(2)
		w.Key("port")
		w.Uint(uint64(b.AppPort))
		w.Key("transport")
		w.Text("tls-v1")
	} else {
		w.Array(0)
	}
	w.Key("caps")
	if b.Sensors {
		w.Array(1)
		w.Text("sensors")
	} else {
		w.Array(0)
	}
	w.Key("device")
	w.Text(device)
	w.Key("Expires")
	w.Uint(uint64(b.Expires))
	w.Key("Issued")
	w.Uint(uint64(b.Issued))
	w.Key("platform")
	w.Text("Lite")
	w.Key("name")
	w.Text(name)
	w.Key("route")
	w.Map(3)
	w.Key("prefix")
	w.Text(b.Device.Prefix())
	w.Key("routerId")
	w.Uint(b.RouterID)
	w.Key("seqno")
	w.Uint(uint64(b.Seqno))
	w.Key("services")
	if b.Services != nil {
		w.Raw(b.Services)
	} else {
		w.Array(0)
	}
	w.Key("version")
	w.Uint(Version)
	return w.Finish()
}

// Digest returns the SHA-256 of the signature preimage, which is the domain,
// u32BE 105, the principal and the body.
func Digest(principal string, body []byte) ([32]byte, error) {
	var sum [32]byte
	if !validPrincipal(principal) || len(body) == 0 || len(body) > BodyMax {
		return sum, ErrInvalid
	}
	d := sha256.New()
	writePreimage(d, principal, body)
	d.Sum(sum[:0])
	return sum, nil
}

type writer interface{ Write([]byte) (int, error) }

func writePreimage(w writer, principal string, body []byte) {
	w.Write([]byte(domain))
	w.Write([]byte{0, 0, 0, addr.PrincipalLen})
	w.Write([]byte(principal))
	w.Write(body)
}

// Sign writes an ASN.1 DER ECDSA signature of body into sig with the device credential.
// The preimage is built in scratch, which is grown when shorter than PreimageSize(body).
func Sign(cred lcrypto.Credential, principal string, body, sig, scratch []byte) (int, error) {
	if !validPrincipal(principal) || len(body) == 0 || len(body) > BodyMax {
		return 0, ErrInvalid
	}
	pre := scratch[:0]
	if cap(pre) < PreimageSize(body) {
		pre = make([]byte, 0, PreimageSize(body))
	}
	pre = append(pre, domain...)
	pre = append(pre, 0, 0, 0, addr.PrincipalLen)
	pre = append(pre, principal...)
	pre = append(pre, body...)
	return cred.Sign(sig, pre, schemeECDSAP256SHA256)
}

// PreimageSize is the length of the signed preimage of body.
func PreimageSize(body []byte) int { return len(domain) + 4 + addr.PrincipalLen + len(body) }

// Verifier checks manifest signatures with a device's P-256 public key.
type Verifier struct {
	ec ecdsa.P256Verifier
}

// Verify checks sig over body by pub, the uncompressed point of the device certificate.
func (v *Verifier) Verify(pub []byte, principal string, body, sig []byte) error {
	if len(sig) < 8 || len(sig) > SignatureMax {
		return ErrSignature
	}
	sum, err := Digest(principal, body)
	if err != nil {
		return err
	}
	if v.ec.VerifyASN1(pub, sum[:], sig) != nil {
		return ErrSignature
	}
	return nil
}

// WriteWire writes the envelope {body, principal, signature}, as wn_manifest_wire_write does.
func WriteWire(w *cbor.Writer, principal string, body, sig []byte) ([]byte, error) {
	if !validPrincipal(principal) || len(body) == 0 || len(body) > BodyMax || len(sig) < 8 || len(sig) > 3309 {
		return nil, ErrInvalid
	}
	w.Map(3)
	w.Key("body")
	w.Raw(body)
	w.Key("principal")
	w.Text(principal)
	w.Key("signature")
	w.Bytes(sig)
	return w.Finish()
}

// Wire is a decoded envelope. Its fields borrow the parsed data.
type Wire struct {
	Body      []byte // The exact signed bytes.
	Principal string
	Signature []byte
}

// ReadWire decodes an envelope parsed into d.
func ReadWire(d *cbor.Doc, out *Wire) error {
	if d.Len(0) != 3 || !d.Fields(0, "body", "principal", "signature") {
		return ErrInvalid
	}
	body := d.Member(0, "body")
	p, err := d.Text(d.Member(0, "principal"))
	if err != nil || d.Kind(body) != cbor.KindMap || !validPrincipal(string(p)) {
		return ErrInvalid
	}
	sig, err := d.Bytes(d.Member(0, "signature"))
	if err != nil || len(sig) < 8 {
		return ErrInvalid
	}
	*out = Wire{Body: d.Raw(body), Principal: string(p), Signature: sig}
	return nil
}

// Decode reads the fields of a body parsed into d. Services is left raw.
func Decode(d *cbor.Doc, b *Body) error {
	if v, err := d.Uint(d.Member(0, "version")); err != nil || v != Version {
		return ErrInvalid
	}
	device, err := d.Text(d.Member(0, "device"))
	if err != nil {
		return ErrInvalid
	}
	if b.Device, err = addr.ParseUUID(string(device)); err != nil {
		return ErrInvalid
	}
	var issued, expires, port, seqno uint64
	if issued, err = d.Uint(d.Member(0, "Issued")); err != nil {
		return ErrInvalid
	} else if expires, err = d.Uint(d.Member(0, "Expires")); err != nil {
		return ErrInvalid
	} else if b.Revision, err = d.Uint(d.Member(0, "revision")); err != nil {
		return ErrInvalid
	} else if port, err = d.Uint(d.Member(0, "agentPort")); err != nil || port == 0 || port > 0xffff {
		return ErrInvalid
	}
	route := d.Member(0, "route")
	if !d.Equal(d.Member(route, "prefix"), b.Device.Prefix()) {
		return ErrInvalid
	} else if b.RouterID, err = d.Uint(d.Member(route, "routerId")); err != nil {
		return ErrInvalid
	} else if seqno, err = d.Uint(d.Member(route, "seqno")); err != nil || seqno > 0xffff {
		return ErrInvalid
	}
	if issued == 0 || expires <= issued || expires-issued > MaxLifetime || issued > 1<<62 {
		return ErrInvalid
	}
	b.Issued, b.Expires = int64(issued), int64(expires)
	b.AgentPort, b.Seqno = uint16(port), uint16(seqno)
	if name, err := d.Text(d.Member(0, "name")); err == nil {
		b.Name = string(name)
	}
	b.Services = d.Raw(d.Member(0, "services"))
	return nil
}

func validPrincipal(p string) bool {
	if len(p) != addr.PrincipalLen || p[:25] != "spiffe://wendy.sh/tenant/" || p[61:69] != "/device/" {
		return false
	}
	_, e1 := addr.ParseUUID(p[25:61])
	_, e2 := addr.ParseUUID(p[69:])
	return e1 == nil && e2 == nil
}

// String returns a short description for logs.
func (b *Body) String() string {
	return b.Device.String() + " rev " + strconv.FormatUint(b.Revision, 10)
}
