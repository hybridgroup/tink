//go:build tinygo

// This example joins a Wendy Net mesh as a leaf over Wi-Fi like wendynet-wifi,
// and shows the latest connection info on an SSD1306 display. See README.md.
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/link"
	"github.com/hybridgroup/tink/pkg/mdns"
	"github.com/hybridgroup/tink/pkg/meshid"
	"github.com/hybridgroup/tink/pkg/tls13"
	lx509 "github.com/soypat/lcrypto/x509"
	"tinygo.org/x/drivers/netdev"
	nl "tinygo.org/x/drivers/netlink"
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
	verifier meshid.Verifier
	conn     tls13.Conn
)

func main() {
	time.Sleep(2 * time.Second)
	initDisplay()
	tenantID, deviceID, err := meshid.Identity(deviceCert)
	check("device certificate", err)
	tenant, _ := addr.ParseUUID(tenantID)
	self, _ := addr.ParseUUID(deviceID)
	println("device", deviceID)

	// The 1 KiB TCP window keeps at most 2 router segments in flight, so 4 ring slots suffice.
	// The leaf sends at most a control frame of about 1.1 KiB, so a 2 KiB send buffer suffices.
	wifi := esplink.Esplink{RxRingSize: 4, TCP: esplink.TCPConfig{TxBufSize: 2048}}
	netdev.UseNetdev(&wifi)
	state("wifi " + ssid)
	check("wifi", wifi.NetConnect(&nl.ConnectParams{Ssid: ssid, Passphrase: password}))
	if ip, err := wifi.Addr(); err == nil {
		localIP = ip.String()
	}
	state("ntp")
	offset, err := wifi.NTP("pool.ntp.org", 5*time.Second, 3)
	check("ntp", err)
	runtime.AdjustTimeOffset(int64(offset))
	println("time", time.Now().String())

	check("credential", cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{deviceCert}, Key: deviceKey}))
	check("tls config", conn.Configure(tls13.Config{
		Rand:         rand.Reader,
		Suites:       []tls13.Suite{tls13.AES128GCMSHA256()},
		KeyExchanges: []tls13.KeyExchange{tls13.X25519(), tls13.P256()},
		Credential:   &cred,
		Verifier:     &verifier,
		ALPN:         "wendy-local-mesh-ble/2",
		MaxRecord:    4096,
	}))

	for {
		err := session(tenant, self)
		println("session ended:", err.Error())
		state("err " + err.Error())
		time.Sleep(5 * time.Second)
	}
}

func session(tenant, self addr.UUID) error {
	target, pin := peer+":43024", ""
	if peer == "" {
		state("mdns")
		c, err := discover(tenant, self)
		if err != nil {
			return err
		}
		ip := c.IPv4
		target = net.IP(ip[:]).String() + ":" + strconv.Itoa(int(c.Port))
		pin = c.Device.String()
		println("found router", pin, "at", target)
	}
	routerIP, _, _ = strings.Cut(target, ":")
	state("dial")
	// mDNS is only a hint, so TLS must authenticate the device it named.
	err := verifier.Configure(meshid.Config{
		Roots:    lx509.Chain{tenantRoot},
		Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant:   tenant.String(), Device: self.String(), Peer: pin,
	})
	if err != nil {
		return err
	}
	tcp, err := net.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer tcp.Close()
	if err := conn.Open(tcp); err != nil {
		return err
	}
	state("tls")
	// A peer that stalls the handshake must not hang the leaf.
	tcp.SetDeadline(time.Now().Add(30 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	tcp.SetDeadline(time.Time{})
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
	state("linked " + time.Now().Format("15:04:05") + " UTC")
	return l.Run(&conn, nil)
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

func check(what string, err error) {
	for err != nil {
		println(what, "failed:", err.Error())
		state(what + " " + err.Error())
		time.Sleep(time.Second)
	}
}
