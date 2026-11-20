//go:build tinygo

// This example joins a Wendy Net mesh as a leaf over Wi-Fi, dialing one Lite router on TCP 43024.
// See README.md for credentials and the flash command.
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/link"
	"github.com/hybridgroup/tink/pkg/mdns"
	"github.com/hybridgroup/tink/pkg/meshid"
	"github.com/soypat/lcrypto"
	"github.com/soypat/lcrypto/p256"
	"github.com/soypat/lcrypto/x25519"
	lx509 "github.com/soypat/lcrypto/x509"
	"github.com/soypat/lneto/crypto/tlsauto"
	"tinygo.org/x/drivers/netdev"
	nl "tinygo.org/x/drivers/netlink"
	"tinygo.org/x/espradio/hwcrypto"
	esplink "tinygo.org/x/espradio/netlink"
)

var (
	ssid     string
	password string
	peer     string // Router IPv4 address. Found with mDNS when empty.
)

var (
	//go:embed creds/device-cert.der
	deviceCert []byte
	//go:embed creds/device-key.der
	deviceKey []byte
	//go:embed creds/tenant-root.der
	tenantRoot []byte
)

// Large state lives in package variables to keep it off small task stacks.
var (
	cred     lx509.Credential
	signer   lx509.P256Signer
	signers  = [...]lx509.KeySigner{&signer}
	verifier meshid.Verifier
)

func main() {
	time.Sleep(2 * time.Second)
	tenantID, deviceID, err := meshid.Identity(deviceCert)
	check("device certificate", err)
	tenant, _ := addr.ParseUUID(tenantID)
	self, _ := addr.ParseUUID(deviceID)
	println("device", deviceID)

	// The 1 KiB TCP window keeps at most 2 router segments in flight, so 4 ring slots suffice.
	// The leaf sends at most a control frame of about 1.1 KiB, so a 2 KiB send buffer suffices.
	wifi := esplink.Esplink{RxRingSize: 4, TCP: esplink.TCPConfig{TxBufSize: 2048}, TLSHandshakeTimeout: 30 * time.Second}
	check("credential", cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{deviceCert}, Key: deviceKey, Signers: signers[:]}))
	esplink.UseTLS(&wifi, &tlsauto.Config{
		Rand:   rand.Reader,
		Suites: []tlsauto.Suite{hwcrypto.TLSAES128GCMSHA256()},
		KeyExchanges: []tlsauto.KeyExchange{
			{ID: x25519.GroupID, ClientShareLen: x25519.ShareSize, ServerShareLen: x25519.ShareSize, SharedLen: x25519.SharedSize,
				NewExchanger: func() tlsauto.Exchanger { return new(x25519.Exchanger) }},
			{ID: p256.GroupID, ClientShareLen: p256.ShareSize, ServerShareLen: p256.ShareSize, SharedLen: p256.SharedSize,
				NewExchanger: func() tlsauto.Exchanger { return new(p256.Exchanger) }},
		},
		Credential: &cred,
		Verifier:   peerVerifier{&verifier},
		ALPN:       "wendy-local-mesh-ble/2",
		MaxRecord:  4096,
	})
	netdev.UseNetdev(&wifi)
	check("wifi", wifi.NetConnect(&nl.ConnectParams{Ssid: ssid, Passphrase: password}))
	offset, err := wifi.NTP("pool.ntp.org", 5*time.Second, 3)
	check("ntp", err)
	runtime.AdjustTimeOffset(int64(offset))
	println("time", time.Now().String())

	for {
		err := session(tenant, self)
		println("session ended:", err.Error())
		time.Sleep(5 * time.Second)
	}
}

func session(tenant, self addr.UUID) error {
	target, pin := peer+":43024", ""
	if peer == "" {
		c, err := discover(tenant, self)
		if err != nil {
			return err
		}
		ip := c.IPv4
		target = net.IP(ip[:]).String() + ":" + strconv.Itoa(int(c.Port))
		pin = c.Device.String()
		println("found router", pin, "at", target)
	}
	// mDNS is only a hint, so TLS must authenticate the device it named.
	err := verifier.Configure(meshid.Config{
		Roots:    lx509.Chain{tenantRoot},
		Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant:   tenant.String(), Device: self.String(), Peer: pin,
	})
	if err != nil {
		return err
	}
	conn, err := net.DialTLS(target)
	if err != nil {
		return err
	}
	defer conn.Close()
	router, err := addr.ParseUUID(verifier.Device())
	if err != nil {
		return err
	}
	println("tls ok, router", router.String())
	l, err := link.New(link.Config{
		Tenant: tenant, Self: self, Peer: router, Credential: &cred,
		// Babel takes the router id from the last 8 bytes of the address, wire.c wb_decode.
		RouterID: binary.BigEndian.Uint64(self[8:]),
		NowMS:    func() int64 { return time.Now().UnixMilli() },
		OnPacket: func(p []byte) { println("packet", len(p), "bytes") },
	})
	if err != nil {
		return err
	}
	return l.Run(conn, nil)
}

var mdnsBuf [1500]byte

// discover sends legacy unicast mDNS queries until a router of the tenant answers.
func discover(tenant, self addr.UUID) (mdns.Candidate, error) {
	conn, err := net.Dial("udp", "224.0.0.251:5353")
	if err != nil {
		return mdns.Candidate{}, err
	}
	defer conn.Close()
	for id := uint16(1); id <= 5; id++ {
		if _, err := conn.Write(mdns.WriteQuery(mdnsBuf[:], id)); err != nil {
			return mdns.Candidate{}, err
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, err := conn.Read(mdnsBuf[:])
			if err != nil {
				break
			}
			found, err := mdns.Parse(mdnsBuf[:n])
			if err != nil {
				continue
			}
			for i := range found {
				if c, ok := found[i].Candidate(tenant, self); ok {
					return c, nil
				}
			}
		}
	}
	return mdns.Candidate{}, errNoRouter
}

var errNoRouter = errors.New("no router found with mDNS")

// peerVerifier passes the tlsauto chain to meshid, which takes the lcrypto CertChain type.
type peerVerifier struct{ *meshid.Verifier }

func (v peerVerifier) VerifyPeer(c tlsauto.CertChain, scheme uint16, peerIsServer bool, name, msg, sig []byte) error {
	return v.Verifier.VerifyPeer(lcrypto.CertChain(c), scheme, peerIsServer, name, msg, sig)
}

func check(what string, err error) {
	for err != nil {
		println(what, "failed:", err.Error())
		time.Sleep(time.Second)
	}
}
