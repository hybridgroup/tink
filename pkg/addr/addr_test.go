package addr

import (
	"bytes"
	"testing"

	"github.com/hybridgroup/tink/internal/litegolden"
)

func TestMatchesLite(t *testing.T) {
	peer, err := ParseUUID(litegolden.Peer)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := ParseUUID(litegolden.Tenant)
	if a := peer.Address(); !bytes.Equal(a[:], litegolden.Get("address")) {
		t.Errorf("address %x", a)
	}
	if p := peer.Prefix(); p != string(litegolden.Get("prefix")) {
		t.Errorf("prefix %s", p)
	}
	principal := Principal(tenant, peer)
	if principal != string(litegolden.Get("principal")) {
		t.Errorf("principal %s", principal)
	}
	if d, err := PrincipalDevice(principal, tenant); err != nil || d != peer {
		t.Errorf("device %v %v", d, err)
	}
	if peer.String() != litegolden.Peer {
		t.Errorf("string %s", peer)
	}
}

func TestParseUUID(t *testing.T) {
	for _, s := range []string{
		"0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D",
		"0a1b2c3d4e5f-4a6b-8c7d-9e0f1a2b3c4d0",
		"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4",
	} {
		if _, err := ParseUUID(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestDeviceHostname(t *testing.T) {
	peer, _ := ParseUUID(litegolden.Peer)
	for _, h := range []string{
		"device-" + litegolden.Peer + ".wendy.internal",
		"DEVICE-0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D.Wendy.Internal.",
		"device-" + litegolden.Peer + ".mesh.local",
	} {
		u, ok, err := ParseDeviceHostname(h)
		if !ok || err != nil || u != peer {
			t.Errorf("%s: %v %v %v", h, u, ok, err)
		}
	}
	if _, ok, _ := ParseDeviceHostname("example.com"); ok {
		t.Error("ordinary name matched")
	}
	if _, ok, err := ParseDeviceHostname("device-0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3cxx.wendy.internal"); !ok || err == nil {
		t.Error("malformed device name not reported")
	}
}
