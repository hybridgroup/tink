package tls13

import (
	"hash"

	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/aesgcm"
	"github.com/soypat/lcrypto/p256"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/x25519"
	"github.com/soypat/lneto/crypto/tlsraw"
)

// Suite is a TLS 1.3 cipher suite, RFC 8446 B.4.
type Suite struct {
	ID      uint16
	KeyLen  int
	NewAEAD func() lcrypto.AEADCipher
	// NewHash must return a new instance on every call.
	NewHash func() hash.Hash
}

// KeyExchange is a key share group, RFC 8446 4.2.8.
type KeyExchange struct {
	ID             uint16
	ClientShareLen int
	ServerShareLen int
	SharedLen      int
	NewExchanger   func() lcrypto.Exchanger
}

// AES128GCMSHA256 is TLS_AES_128_GCM_SHA256.
func AES128GCMSHA256() Suite {
	return Suite{
		ID:      uint16(tlsraw.SuiteAES128GCMSHA256),
		KeyLen:  16,
		NewAEAD: func() lcrypto.AEADCipher { return new(aesgcm.Cipher) },
		NewHash: func() hash.Hash { return sha256.New() },
	}
}

// X25519 is the x25519 group.
func X25519() KeyExchange {
	return KeyExchange{
		ID:             x25519.GroupID,
		ClientShareLen: x25519.ShareSize,
		ServerShareLen: x25519.ShareSize,
		SharedLen:      x25519.SharedSize,
		NewExchanger:   func() lcrypto.Exchanger { return new(x25519.Exchanger) },
	}
}

// P256 is the secp256r1 group.
func P256() KeyExchange {
	return KeyExchange{
		ID:             p256.GroupID,
		ClientShareLen: p256.ShareSize,
		ServerShareLen: p256.ShareSize,
		SharedLen:      p256.SharedSize,
		NewExchanger:   func() lcrypto.Exchanger { return new(p256.Exchanger) },
	}
}

// DefaultSchemes are the signature schemes offered when Config.Schemes is empty.
var DefaultSchemes = []uint16{
	uint16(tlsraw.SigECDSAP256SHA256),
	uint16(tlsraw.SigEd25519),
	uint16(tlsraw.SigECDSAP384SHA384),
	uint16(tlsraw.SigRSAPSSRSAESHA256),
	uint16(tlsraw.SigRSAPSSRSAESHA384),
	uint16(tlsraw.SigRSAPSSRSAESHA512),
}
