package sniff

import (
	"crypto/aes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var rfcDCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// Key schedule against RFC 9001 A.1 and RFC 9369 A.1.
func TestQUICInitialKeys(t *testing.T) {
	for _, tt := range []struct {
		version              uint32
		initial, key, iv, hp string
	}{
		{1, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
			"1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"},
		{0x6b3343cf, "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba",
			"8b1a0bc121284290a29e0971b5cd045d", "91f73e2351d8fa91660e909f", "45b95e15235d6f45a6b19cbcb0294ba9"},
	} {
		v := quicVersions[tt.version]
		initial, _ := hkdf.Extract(sha256.New, rfcDCID, v.salt)
		if hex.EncodeToString(initial) != tt.initial {
			t.Errorf("%#x initial_secret %x", tt.version, initial)
		}
		client, _ := expandLabel(initial, "client in", 32)
		for _, f := range []struct {
			label, want string
			n           int
		}{{v.keyLabel, tt.key, 16}, {v.ivLabel, tt.iv, 12}, {v.hpLabel, tt.hp, 16}} {
			if got, _ := expandLabel(client, f.label, f.n); hex.EncodeToString(got) != f.want {
				t.Errorf("%#x %s = %x, want %s", tt.version, f.label, got, f.want)
			}
		}
	}
}

// The protected client Initial packets of RFC 9001 A.2 and RFC 9369 A.2.
func TestQUICRFCPackets(t *testing.T) {
	for _, f := range []string{"rfc9001-client-initial.hex", "rfc9369-client-initial.hex"} {
		data, err := os.ReadFile("testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		var q QUIC
		res, done := q.Add(mustHex(t, string(data)))
		if !done || res.Protocol != "quic" || res.Host != "example.com" || res.ECH {
			t.Errorf("%s: %+v done=%v", f, res, done)
		}
	}
}

// sealInitial builds a protected QUIC v1 client Initial packet carrying the
// given frames, padded to fill a 1200-byte datagram unless noPad.
func sealInitial(t *testing.T, dcid []byte, pn uint32, frames []byte, noPad bool) []byte {
	t.Helper()
	var q QUIC
	k, err := q.initialKeys(quicVersions[1], dcid)
	if err != nil {
		t.Fatal(err)
	}
	hdr := []byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0, 0) // no SCID, no token
	payload := append([]byte(nil), frames...)
	if !noPad {
		for len(hdr)+2+4+len(payload)+16 < 1200 {
			payload = append(payload, 0)
		}
	}
	length := 4 + len(payload) + 16
	hdr = append(hdr, 0x40|byte(length>>8), byte(length))
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)
	nonce := append([]byte(nil), k.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(uint64(pn) >> (8 * i))
	}
	pkt := k.aead.Seal(append([]byte(nil), hdr...), nonce, payload, hdr)
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func cryptoFrame(off int, data []byte) []byte {
	f := []byte{0x06, 0x80 | byte(off>>24), byte(off >> 16), byte(off >> 8), byte(off)} // 4-byte varint offset
	f = append(f, 0x40|byte(len(data)>>8), byte(len(data)))
	return append(f, data...)
}

func TestQUICClientHelloAcrossDatagrams(t *testing.T) {
	// A real ClientHello (crypto/tls sends a post-quantum key share, so it
	// is well over 1 KB), without the TLS record header.
	rec := clientHello(t, &tls.Config{ServerName: "Chat.OpenAI.com", NextProtos: []string{"h3"}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	hello := rec[5:]
	if len(hello) < 1000 {
		t.Logf("ClientHello is only %d bytes", len(hello))
	}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	half := len(hello) / 2
	// Second half first, like Chrome's shuffled CRYPTO frames; with an ACK
	// and PING mixed in.
	p1 := sealInitial(t, dcid, 0, append([]byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00}, cryptoFrame(half, hello[half:])...), false)
	p2 := sealInitial(t, dcid, 1, cryptoFrame(0, hello[:half]), false)

	var q QUIC
	if res, done := q.Add(p1); done {
		t.Fatalf("done after half a ClientHello: %+v", res)
	}
	res, done := q.Add(p2)
	if !done || res.Protocol != "quic" || res.Host != "chat.openai.com" || res.ECH {
		t.Fatalf("got %+v done=%v", res, done)
	}

	// Both packets coalesced into one datagram.
	a := sealInitial(t, dcid, 2, cryptoFrame(0, hello[:half]), true)
	b := sealInitial(t, dcid, 3, cryptoFrame(half, hello[half:]), true)
	var q2 QUIC
	if res, done := q2.Add(append(a, b...)); !done || res.Host != "chat.openai.com" {
		t.Fatalf("coalesced: %+v done=%v", res, done)
	}
}

func TestQUICNotQUIC(t *testing.T) {
	for name, dgram := range map[string][]byte{
		"dns":          mustHex(t, "abcd0100000100000000000003777777076578616d706c6503636f6d0000010001"),
		"short header": append([]byte{0x40}, make([]byte, 40)...),
		"empty":        {},
		"unknown ver":  append([]byte{0xc0, 0xff, 0, 0, 0x1d, 8}, make([]byte, 60)...),
	} {
		var q QUIC
		if res, done := q.Add(dgram); !done || res != (Result{}) {
			t.Errorf("%s: %+v done=%v", name, res, done)
		}
	}
	// A tampered Initial fails authentication: not treated as QUIC.
	data, _ := os.ReadFile("testdata/rfc9001-client-initial.hex")
	pkt := mustHex(t, string(data))
	pkt[len(pkt)-1] ^= 1
	var q QUIC
	if res, done := q.Add(pkt); !done || res.Host != "" {
		t.Errorf("tampered: %+v done=%v", res, done)
	}
}

// A ClientHello that never completes stops after maxQUICPackets datagrams.
func TestQUICGivesUp(t *testing.T) {
	dcid := []byte{9, 9, 9, 9}
	var q QUIC
	part := sealInitial(t, dcid, 0, cryptoFrame(100, []byte("x")), false) // offset 0 never arrives
	for i := 1; i < maxQUICPackets; i++ {
		if _, done := q.Add(part); done {
			t.Fatalf("gave up after %d datagrams", i)
		}
	}
	if res, done := q.Add(part); !done || res.Host != "" || res.Protocol != "quic" {
		t.Fatalf("got %+v done=%v", res, done)
	}
}
