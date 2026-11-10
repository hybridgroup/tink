package mdns

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/hybridgroup/tink/pkg/addr"
)

const (
	tenantID = "2558fd76-afc7-466e-9613-6b715296a526"
	routerID = "00000000-0000-4000-8000-000000000004"
)

func uuid(s string) addr.UUID {
	u, err := addr.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}

func principal() string { return addr.Principal(uuid(tenantID), uuid(routerID)) }

func name(b []byte, s string) []byte { return appendName(b, s) }

func rr(b []byte, owner string, typ uint16, data []byte) []byte {
	b = name(b, owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 0x8001)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func txt(kv ...string) []byte {
	var b []byte
	for _, s := range kv {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b
}

// response builds an answer like ESP-IDF mdns, with the instance name compressed.
func response(extra ...string) []byte {
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0}
	inst := "lite-router." + Service
	b = rr(b, Service, typePTR, name(nil, inst))
	srv := []byte{0, 0, 0, 0, 0xa8, 0x10}
	b = rr(b, inst, typeSRV, name(srv, "lite.local"))
	kv := append([]string{"version=1", "protocol=tls-v1", "principal=" + principal(),
		"mesh=x", "role=embedded-router", "platform=Lite", "operator_router=0"}, extra...)
	b = rr(b, inst, typeTXT, txt(kv...))
	b = rr(b, "lite.local", typeA, []byte{192, 168, 1, 20})
	return b
}

func TestQuery(t *testing.T) {
	q := WriteQuery(make([]byte, QueryMax), 7)
	want := []byte{0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		10, '_', 'w', 'e', 'n', 'd', 'y', '-', 'n', 'e', 't', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 12, 0x80, 1}
	if string(q) != string(want) {
		t.Fatalf("%x", q)
	}
}

func TestParse(t *testing.T) {
	ins, err := Parse(response())
	if err != nil || len(ins) != 1 {
		t.Fatal(ins, err)
	}
	c, ok := ins[0].Candidate(uuid(tenantID), uuid("00000000-0000-4000-8000-000000000005"))
	if !ok || c.Device != uuid(routerID) || c.IPv4 != [4]byte{192, 168, 1, 20} || c.Port != 43024 {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := ins[0].Candidate(uuid(tenantID), uuid(routerID)); ok {
		t.Error("accepted our own advertisement")
	}
	if _, ok := ins[0].Candidate(uuid("3558fd76-afc7-466e-9613-6b715296a526"), uuid(routerID)); ok {
		t.Error("accepted another tenant")
	}
	ins, _ = Parse(response("role=router"))
	if _, ok := ins[0].Candidate(uuid(tenantID), addr.UUID{}); ok {
		t.Error("accepted a repeated role key")
	}
}

func TestParseCompressionLoop(t *testing.T) {
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12}
	if _, err := Parse(b); err == nil {
		t.Fatal("accepted a pointer loop")
	}
}

// TestAvahi browses a service published with avahi-publish through a real
// legacy unicast query. It needs avahi-daemon and TINK_MDNS_AVAHI=1.
func TestAvahi(t *testing.T) {
	if os.Getenv("TINK_MDNS_AVAHI") == "" {
		t.Skip("TINK_MDNS_AVAHI not set")
	}
	pub := exec.Command("avahi-publish", "-s", "tink-mdns-test", "_wendy-net._tcp", "43024",
		"version=1", "protocol=tls-v1", "principal="+principal(), "role=embedded-router")
	if err := pub.Start(); err != nil {
		t.Fatal(err)
	}
	defer pub.Process.Kill()
	time.Sleep(2 * time.Second)
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	group := &net.UDPAddr{IP: net.IP(Group[:]), Port: Port}
	buf := make([]byte, 9000)
	for try := 0; try < 5; try++ {
		conn.WriteToUDP(WriteQuery(make([]byte, QueryMax), uint16(try+1)), group)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			ins, err := Parse(buf[:n])
			if err != nil {
				t.Logf("from %v: %v", from, err)
				continue
			}
			for _, in := range ins {
				if c, ok := in.Candidate(uuid(tenantID), addr.UUID{}); ok && c.Device == uuid(routerID) {
					t.Logf("found %s at %v:%d from %v", in.Name, c.IPv4, c.Port, from)
					return
				}
			}
		}
	}
	t.Fatal("no answer from avahi")
}
