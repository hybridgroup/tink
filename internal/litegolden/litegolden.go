// Package litegolden holds wire vectors printed by the wendy-lite C code.
// Regenerate vectors.txt with gen.sh.
package litegolden

import (
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed vectors.txt
var vectors string

// Tenant, Self and Peer are the UUIDs gen.c uses.
const (
	Tenant = "2558fd76-afc7-466e-9613-6b715296a526"
	Self   = "00000000-0000-4000-8000-000000000001"
	Peer   = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// Get returns the vector called name. It panics if there is none.
func Get(name string) []byte {
	for _, line := range strings.Split(vectors, "\n") {
		k, v, ok := strings.Cut(line, " ")
		if ok && k == name {
			b, err := hex.DecodeString(v)
			if err != nil {
				panic(err)
			}
			return b
		}
	}
	panic("litegolden: no vector " + name)
}
