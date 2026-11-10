// Package addr holds Wendy Net device identifiers: UUIDs, mesh IPv6
// addresses and SPIFFE principals, as in wendy-lite components/wendy_net_peer/src/protocol.c.
package addr

import (
	"errors"
	"strconv"
)

// UUID is a device or tenant UUID.
type UUID [16]byte

var ErrUUID = errors.New("addr: invalid UUID")

const (
	principalPrefix = "spiffe://wendy.sh/tenant/"
	PrincipalLen    = 105
)

// meshPrefix is the device ULA fd45:b891:567f::/48.
var meshPrefix = [6]byte{0xfd, 0x45, 0xb8, 0x91, 0x56, 0x7f}

// ParseUUID parses the lowercase canonical form, as wn_uuid_parse does.
func ParseUUID(s string) (u UUID, err error) {
	if len(s) != 36 {
		return u, ErrUUID
	}
	n := 0
	for i := 0; i < 36; {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return u, ErrUUID
			}
			i++
			continue
		}
		a, b := hexVal(s[i]), hexVal(s[i+1])
		if a < 0 || b < 0 {
			return u, ErrUUID
		}
		u[n] = byte(a<<4 | b)
		n++
		i += 2
	}
	return u, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// String returns the lowercase canonical form.
func (u UUID) String() string {
	const hex = "0123456789abcdef"
	var b [36]byte
	n := 0
	for i, c := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b[n] = '-'
			n++
		}
		b[n], b[n+1] = hex[c>>4], hex[c&15]
		n += 2
	}
	return string(b[:])
}

// Address returns the device mesh address: fd45:b891:567f followed by bytes 6..15 of the UUID.
func (u UUID) Address() (a [16]byte) {
	copy(a[:], meshPrefix[:])
	copy(a[6:], u[6:])
	return a
}

// Prefix returns the device route prefix in the form wn_prefix writes.
func (u UUID) Prefix() string {
	a := u.Address()
	s := "fd45:b891:567f"
	for i := 6; i < 16; i += 2 {
		s += ":" + strconv.FormatUint(uint64(a[i])<<8|uint64(a[i+1]), 16)
	}
	return s + "/128"
}

// Principal returns spiffe://wendy.sh/tenant/<tenant>/device/<device>.
func Principal(tenant, device UUID) string {
	return principalPrefix + tenant.String() + "/device/" + device.String()
}

// PrincipalDevice returns the device of a principal that belongs to tenant.
func PrincipalDevice(principal string, tenant UUID) (UUID, error) {
	if len(principal) != PrincipalLen {
		return UUID{}, ErrUUID
	}
	d, err := ParseUUID(principal[PrincipalLen-36:])
	if err != nil || Principal(tenant, d) != principal {
		return UUID{}, ErrUUID
	}
	return d, nil
}

// ParseDeviceHostname parses device-<uuid>.wendy.internal and the legacy
// .mesh.wendy.internal and .mesh.local names, case insensitive with an
// optional trailing dot. ok is false for any other name.
func ParseDeviceHostname(host string) (u UUID, ok bool, err error) {
	if n := len(host); n > 0 && host[n-1] == '.' {
		host = host[:n-1]
	}
	for _, suffix := range [...]string{".wendy.internal", ".mesh.wendy.internal", ".mesh.local"} {
		if len(host) != 7+36+len(suffix) || !equalFold(host[:7], "device-") || !equalFold(host[43:], suffix) {
			continue
		}
		var b [36]byte
		for i := range 36 {
			c := host[7+i]
			if c >= 'A' && c <= 'F' {
				c += 'a' - 'A'
			}
			b[i] = c
		}
		u, err = ParseUUID(string(b[:]))
		return u, true, err
	}
	return u, false, nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
