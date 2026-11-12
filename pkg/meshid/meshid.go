// Package meshid authenticates Wendy Net device peers during TLS. It mirrors
// the peer check of wendy-lite components/wendy_pki/src/wendy_pki_tls.c finish_mesh.
package meshid

import (
	"errors"
	"sync"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/ecdsa"
	"github.com/soypat/lcrypto/sha256"
	lx509 "github.com/soypat/lcrypto/x509"
)

const (
	prefix       = "spiffe://wendy.sh/tenant/"
	uuidLen      = 36
	principalLen = len(prefix) + uuidLen + len("/device/") + uuidLen // 105
	devicePos    = principalLen - uuidLen
)

var (
	ErrTenant    = errors.New("meshid: invalid tenant")
	ErrPrincipal = errors.New("meshid: peer principal is not one device of the tenant")
	ErrSelf      = errors.New("meshid: peer is this device")
	ErrUnpinned  = errors.New("meshid: peer is not the pinned device")
	ErrScheme    = errors.New("meshid: unsupported signature scheme")
	errSAN       = errors.New("meshid: malformed subject alternative name")
)

// Config configures a Verifier.
type Config struct {
	// Roots are the tenant trust anchors as DER certificates.
	Roots lcrypto.CertChain
	// Nanotime returns wall clock nanoseconds since the Unix epoch.
	Nanotime func() int64
	// Tenant and Device are this node's UUIDs. A peer with the same device UUID is rejected.
	Tenant, Device string
	// Peer pins one peer device UUID when set.
	Peer string
}

// Verifier implements lcrypto.Verifier for Wendy device certificates. Every
// peer leaf must carry exactly one SAN URI spiffe://wendy.sh/tenant/<tenant>/device/<uuid>.
type Verifier struct {
	mu        sync.Mutex
	chain     lx509.Verifier
	p256      lx509.P256Verifier
	algs      [1]lx509.SignatureVerifier
	self      [principalLen]byte
	peer      [uuidLen]byte
	pinned    bool
	leaf      lx509.Certificate
	ec        ecdsa.P256Verifier
	digest    sha256.Digest
	sum       [32]byte
	principal [principalLen]byte
	verified  bool
}

var _ lcrypto.Verifier = (*Verifier)(nil)

// Configure checks cfg. On error v is left unconfigured.
func (v *Verifier) Configure(cfg Config) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verified = false
	if !isUUID(cfg.Tenant) || !isUUID(cfg.Device) || (cfg.Peer != "" && !isUUID(cfg.Peer)) {
		return ErrTenant
	}
	v.algs[0] = &v.p256
	err := v.chain.Configure(lx509.VerifierConfig{
		Algorithms:         v.algs[:],
		Roots:              cfg.Roots,
		Nanotime:           cfg.Nanotime,
		MaxChainLen:        8,
		MaxSignatureChecks: 16,
	})
	if err != nil {
		return err
	}
	n := copy(v.self[:], prefix)
	n += copy(v.self[n:], cfg.Tenant)
	n += copy(v.self[n:], "/device/")
	copy(v.self[n:], cfg.Device)
	v.pinned = cfg.Peer != ""
	copy(v.peer[:], cfg.Peer)
	return nil
}

// VerifyPeer implements lcrypto.Verifier. expectName is ignored since the
// identity is the SPIFFE principal, not a host name.
func (v *Verifier) VerifyPeer(chainView lcrypto.CertChain, scheme uint16, peerIsServer bool, expectName, msg, sig []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verified = false
	usage := lx509.ExtKeyUsageClientAuth
	if peerIsServer {
		usage = lx509.ExtKeyUsageServerAuth
	}
	if err := v.chain.VerifyChainAnyName(chainView, usage); err != nil {
		return err
	}
	der, err := chainView.CertView(0)
	if err != nil {
		return err
	} else if err = v.leaf.Parse(der); err != nil {
		return err
	}
	if err = v.checkPrincipal(v.leaf.SubjectAltName); err != nil {
		return err
	}
	if scheme != lx509.SchemeECDSAP256SHA256 || v.leaf.PublicKeyAlgorithm != lx509.ECDSAP256 {
		return ErrScheme
	}
	v.digest.Init()
	v.digest.Write(msg)
	v.digest.Sum(v.sum[:0])
	if err = v.ec.VerifyASN1(v.leaf.PublicKey, v.sum[:], sig); err != nil {
		return err
	}
	v.verified = true
	return nil
}

// Principal returns the last verified peer principal, or "" if the last check failed.
func (v *Verifier) Principal() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.verified {
		return ""
	}
	return string(v.principal[:])
}

// Device returns the last verified peer device UUID, or "" if the last check failed.
func (v *Verifier) Device() string {
	if p := v.Principal(); p != "" {
		return p[devicePos:]
	}
	return ""
}

// checkPrincipal walks the GeneralNames SEQUENCE, RFC 5280 4.2.1.6, and
// requires exactly one URI (tag [6]) that names a device of the tenant.
func (v *Verifier) checkPrincipal(san []byte) error {
	names, ok := readTLV(&san, 0x30)
	if !ok || len(san) != 0 {
		return errSAN
	}
	count := 0
	for len(names) > 0 {
		if len(names) < 2 {
			return errSAN
		}
		tag := names[0]
		value, ok := readTLV(&names, tag)
		if !ok {
			return errSAN
		} else if tag != 0x86 {
			continue
		}
		count++
		if len(value) != principalLen || string(value[:devicePos]) != string(v.self[:devicePos]) ||
			!isUUID(string(value[devicePos:])) {
			return ErrPrincipal
		} else if string(value[devicePos:]) == string(v.self[devicePos:]) {
			return ErrSelf
		} else if v.pinned && string(value[devicePos:]) != string(v.peer[:]) {
			return ErrUnpinned
		}
		copy(v.principal[:], value)
	}
	if count != 1 {
		return ErrPrincipal
	}
	return nil
}

// readTLV reads one DER element of tag from b and returns its contents.
func readTLV(b *[]byte, tag byte) ([]byte, bool) {
	d := *b
	if len(d) < 2 || d[0] != tag {
		return nil, false
	}
	n, off := int(d[1]), 2
	if n&0x80 != 0 {
		w := n & 0x7f
		if w == 0 || w > 2 || len(d) < 2+w {
			return nil, false
		}
		n = 0
		for _, c := range d[2 : 2+w] {
			n = n<<8 | int(c)
		}
		off += w
	}
	if len(d)-off < n {
		return nil, false
	}
	*b = d[off+n:]
	return d[off : off+n], true
}

// isUUID matches the lowercase canonical form, as wendy_identity_uuid does.
func isUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Identity returns the tenant and device UUIDs of a Wendy device
// certificate from its single SPIFFE device URI.
func Identity(der []byte) (tenant, device string, err error) {
	var c lx509.Certificate
	if err = c.Parse(der); err != nil {
		return "", "", err
	}
	san := c.SubjectAltName
	names, ok := readTLV(&san, 0x30)
	if !ok {
		return "", "", errSAN
	}
	found := ""
	for len(names) > 0 {
		tag := names[0]
		value, ok := readTLV(&names, tag)
		if !ok {
			return "", "", errSAN
		} else if tag != 0x86 {
			continue
		}
		if found != "" {
			return "", "", ErrPrincipal
		}
		found = string(value)
	}
	if len(found) != principalLen || found[:len(prefix)] != prefix || found[len(prefix)+uuidLen:devicePos] != "/device/" ||
		!isUUID(found[len(prefix):len(prefix)+uuidLen]) || !isUUID(found[devicePos:]) {
		return "", "", ErrPrincipal
	}
	return found[len(prefix) : len(prefix)+uuidLen], found[devicePos:], nil
}
