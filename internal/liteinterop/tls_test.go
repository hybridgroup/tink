package liteinterop

import (
	"crypto/rand"
	"hash"

	"github.com/hybridgroup/tink/pkg/meshid"
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/aesgcm"
	"github.com/soypat/lcrypto/p256"
	"github.com/soypat/lcrypto/sha256"
	"github.com/soypat/lcrypto/x25519"
	"github.com/soypat/lneto/crypto/tlsauto"
	"github.com/soypat/lneto/crypto/tlsraw"
)

func tlsConfig(cred tlsauto.Credential, v *meshid.Verifier, maxRecord int) tlsauto.Config {
	return tlsauto.Config{
		Rand: rand.Reader,
		Suites: []tlsauto.Suite{{
			ID:      uint16(tlsraw.SuiteAES128GCMSHA256),
			KeyLen:  16,
			NewAEAD: func() tlsauto.AEADCipher { return new(aesgcm.Cipher) },
			NewHash: func() hash.Hash { return sha256.New() },
		}},
		KeyExchanges: []tlsauto.KeyExchange{
			{ID: x25519.GroupID, ClientShareLen: x25519.ShareSize, ServerShareLen: x25519.ShareSize, SharedLen: x25519.SharedSize,
				NewExchanger: func() tlsauto.Exchanger { return new(x25519.Exchanger) }},
			{ID: p256.GroupID, ClientShareLen: p256.ShareSize, ServerShareLen: p256.ShareSize, SharedLen: p256.SharedSize,
				NewExchanger: func() tlsauto.Exchanger { return new(p256.Exchanger) }},
		},
		Credential: cred,
		Verifier:   peerVerifier{v},
		ALPN:       "wendy-local-mesh-ble/2",
		MaxRecord:  maxRecord,
	}
}

// peerVerifier passes the tlsauto chain to meshid, which takes the lcrypto CertChain type.
type peerVerifier struct{ *meshid.Verifier }

func (v peerVerifier) VerifyPeer(c tlsauto.CertChain, scheme uint16, peerIsServer bool, name, msg, sig []byte) error {
	return v.Verifier.VerifyPeer(lcrypto.CertChain(c), scheme, peerIsServer, name, msg, sig)
}
