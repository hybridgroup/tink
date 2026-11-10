package cbor

// keyTable is sorted by name. Keep in sync with wn_key_name in
// wendy-lite components/wendy_net_common/src/binary.c and WendyOS netwire/keys.go.
var keyTable = [...]struct{ name, key string }{
	{"Expires", "e"},
	{"Issued", "i"},
	{"added", "a"},
	{"address", "a"},
	{"agentPort", "P"},
	{"agentTransport", "T"},
	{"appEndpoints", "a"},
	{"appId", "a"},
	{"attachment", "a"},
	{"ble", "b"},
	{"body", "b"},
	{"bundle", "b"},
	{"caps", "c"},
	{"catalog", "C"},
	{"certificate", "c"},
	{"certificates", "c"},
	{"chain", "c"},
	{"chunk", "d"},
	{"credit", "c"},
	{"data", "d"},
	{"datagram", "g"},
	{"device", "d"},
	{"digest", "h"},
	{"endpointListen", "e"},
	{"error", "e"},
	{"ethernet", "E"},
	{"expires", "e"},
	{"fingerprint", "f"},
	{"fingerprints", "f"},
	{"generation", "G"},
	{"gossip", "g"},
	{"hash", "h"},
	{"hashes", "h"},
	{"hello", "h"},
	{"hops", "h"},
	{"hostPort", "h"},
	{"id", "i"},
	{"incarnation", "I"},
	{"index", "i"},
	{"infrastructureWifi", "i"},
	{"instance", "n"},
	{"ipDatagram", "i"},
	{"issued", "i"},
	{"key", "k"},
	{"kind", "k"},
	{"link_id", "l"},
	{"listen", "l"},
	{"live", "l"},
	{"manifest", "m"},
	{"mesh", "m"},
	{"missing", "m"},
	{"mtu", "m"},
	{"name", "n"},
	{"nan", "n"},
	{"nonce", "n"},
	{"offset", "f"},
	{"op", "o"},
	{"operator", "o"},
	{"operatorCertificate", "O"},
	{"operatorReceipts", "o"},
	{"origin", "o"},
	{"peer", "p"},
	{"peers", "p"},
	{"platform", "l"},
	{"port", "p"},
	{"prefix", "p"},
	{"previous", "p"},
	{"principal", "p"},
	{"proof", "p"},
	{"receipts", "c"},
	{"record", "R"},
	{"request", "r"},
	{"requester", "r"},
	{"requires", "q"},
	{"retainUntil", "r"},
	{"revision", "R"},
	{"role", "r"},
	{"route", "r"},
	{"router", "r"},
	{"routerID", "r"},
	{"routerId", "r"},
	{"rx", "r"},
	{"self", "s"},
	{"seqno", "s"},
	{"serviceId", "s"},
	{"services", "s"},
	{"signature", "s"},
	{"stream", "s"},
	{"time", "t"},
	{"total", "l"},
	{"transcript", "t"},
	{"transport", "t"},
	{"tx", "T"},
	{"txt", "x"},
	{"type", "t"},
	{"until", "u"},
	{"used", "u"},
	{"v", "v"},
	{"version", "v"},
	{"withdraw", "w"},
}

// KeyName returns the wire key of a schema field name. Names outside the
// table, and single character names, are sent as they are.
func KeyName(name string) string {
	if name == "owner" {
		return "o"
	} else if len(name) < 2 {
		return name
	}
	lo, hi := 0, len(keyTable)
	for lo < hi {
		mid := lo + (hi-lo)/2
		switch n := keyTable[mid].name; {
		case name == n:
			return keyTable[mid].key
		case name < n:
			hi = mid
		default:
			lo = mid + 1
		}
	}
	return name
}
