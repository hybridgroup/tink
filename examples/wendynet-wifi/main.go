//go:build tinygo

// This example joins a Wendy Net mesh as a leaf over Wi-Fi. It dials one
// Lite router on TCP 43024, runs mutual TLS and keeps the leaf session up.
//
// Put the device credentials from an enrolled device in creds/, see README.md, then
//
//	tinygo flash -target xiao-esp32s3 -ldflags="-X main.ssid=SSID -X main.password=PASS -X main.peer=192.168.1.20" -monitor ./examples/wendynet-wifi
package main

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"net"
	"runtime"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
	"github.com/hybridgroup/tink/pkg/link"
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
	peer     string // Router IPv4 address.
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
	tenantID, deviceID, err := meshid.Identity(deviceCert)
	check("device certificate", err)
	tenant, _ := addr.ParseUUID(tenantID)
	self, _ := addr.ParseUUID(deviceID)
	println("device", deviceID)

	wifi := esplink.Esplink{}
	netdev.UseNetdev(&wifi)
	check("wifi", wifi.NetConnect(&nl.ConnectParams{Ssid: ssid, Passphrase: password}))
	offset, err := wifi.NTP("pool.ntp.org", 5*time.Second, 3)
	check("ntp", err)
	runtime.AdjustTimeOffset(int64(offset))
	println("time", time.Now().String())

	check("credential", cred.Configure(lx509.CredentialConfig{Chain: lx509.Chain{deviceCert}, Key: deviceKey}))
	check("verifier", verifier.Configure(meshid.Config{
		Roots:    lx509.Chain{tenantRoot},
		Nanotime: func() int64 { return time.Now().UnixNano() },
		Tenant:   tenantID, Device: deviceID,
	}))
	check("tls config", conn.Configure(tls13.Config{
		Rand:         rand.Reader,
		Suites:       []tls13.Suite{tls13.AES128GCMSHA256()},
		KeyExchanges: []tls13.KeyExchange{tls13.X25519(), tls13.P256()},
		Credential:   &cred,
		Verifier:     &verifier,
		ALPN:         "wendy-local-mesh-ble/2",
	}))

	for {
		err := session(tenant, self)
		println("session ended:", err.Error())
		time.Sleep(5 * time.Second)
	}
}

func session(tenant, self addr.UUID) error {
	tcp, err := net.Dial("tcp", peer+":43024")
	if err != nil {
		return err
	}
	defer tcp.Close()
	if err := conn.Open(tcp); err != nil {
		return err
	}
	if err := conn.Handshake(); err != nil {
		return err
	}
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
		Log:      func(msg string) { println(msg) },
	})
	if err != nil {
		return err
	}
	go report(l)
	return l.Run(&conn, nil)
}

func report(l *link.Link) {
	for was := false; ; time.Sleep(time.Second) {
		if up := l.Up(); up != was {
			println("babel link up:", up)
			was = up
		}
	}
}

func check(what string, err error) {
	for err != nil {
		println(what, "failed:", err.Error())
		time.Sleep(time.Second)
	}
}
