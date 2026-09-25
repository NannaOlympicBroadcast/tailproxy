package sniff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// QUIC reads the server_name of a QUIC connection from the client's
// Initial packets (DESIGN §4.7). Their protection keys derive from the
// Destination Connection ID the client chose, not from any secret (RFC
// 9001 §5.2), so the ClientHello can be read without the server's keys.
// The ClientHello may span several Initial packets (post-quantum key
// shares make it larger than one datagram), so datagrams are fed one by
// one until it is complete. Nothing is modified; the caller forwards the
// datagrams unchanged.
type QUIC struct {
	frags   map[uint64][]byte // CRYPTO frame data by stream offset
	total   int
	packets int
	keys    map[string]*initialKeys // by DCID
}

// Limits: a ClientHello is at most a few KB.
const (
	maxQUICCrypto  = 64 << 10
	maxQUICPackets = 16
)

type quicVersion struct {
	salt                       []byte
	keyLabel, ivLabel, hpLabel string
	initialType                byte // long header packet type bits for Initial
}

var quicVersions = map[uint32]quicVersion{
	// RFC 9001 §5.2.
	0x00000001: {salt: []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a},
		keyLabel: "quic key", ivLabel: "quic iv", hpLabel: "quic hp", initialType: 0},
	// RFC 9369 §3.3.
	0x6b3343cf: {salt: []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9},
		keyLabel: "quicv2 key", ivLabel: "quicv2 iv", hpLabel: "quicv2 hp", initialType: 1},
}

type initialKeys struct {
	aead cipher.AEAD
	iv   []byte
	hp   cipher.Block
}

var errNotInitial = errors.New("not a QUIC Initial packet")

// Add feeds one datagram from the client. done reports that no more
// datagrams are needed: either the ClientHello was read (res.Host, res.ECH;
// res.Protocol is "quic"), or the flow is not QUIC, or reading failed.
func (q *QUIC) Add(dgram []byte) (res Result, done bool) {
	q.packets++
	found := false
	for len(dgram) > 0 {
		n, err := q.addPacket(dgram)
		if err != nil {
			break // short header, padding or garbage after the Initial(s)
		}
		found = true
		dgram = dgram[n:]
	}
	if !found && q.frags == nil {
		return Result{}, true // the first datagram is not a QUIC Initial
	}
	if hello, ok := q.clientHello(); ok {
		host, ech, ok := parseClientHello(hello)
		if !ok {
			return Result{Protocol: "quic"}, true
		}
		return Result{Protocol: "quic", Host: normalize(host), ECH: ech}, true
	}
	if q.packets >= maxQUICPackets || q.total > maxQUICCrypto {
		return Result{Protocol: "quic"}, true
	}
	return Result{}, false
}

// addPacket decrypts one Initial packet at the start of b and collects its
// CRYPTO frames; it returns the packet's length. Other long header
// packets are skipped.
func (q *QUIC) addPacket(b []byte) (int, error) {
	if len(b) < 7 || b[0]&0x80 == 0 {
		return 0, errNotInitial
	}
	v, ok := quicVersions[binary.BigEndian.Uint32(b[1:5])]
	if !ok {
		return 0, errNotInitial
	}
	p := 5
	dcidLen := int(b[p])
	if dcidLen > 20 || len(b) < p+1+dcidLen+1 {
		return 0, errNotInitial
	}
	dcid := b[p+1 : p+1+dcidLen]
	p += 1 + dcidLen
	scidLen := int(b[p])
	if scidLen > 20 || len(b) < p+1+scidLen {
		return 0, errNotInitial
	}
	p += 1 + scidLen
	isInitial := (b[0]>>4)&3 == v.initialType
	if isInitial {
		tokenLen, n := varint(b[p:])
		if n == 0 || uint64(len(b)-p-n) < tokenLen {
			return 0, errNotInitial
		}
		p += n + int(tokenLen)
	}
	length, n := varint(b[p:])
	if n == 0 || uint64(len(b)-p-n) < length {
		return 0, errNotInitial
	}
	p += n
	end := p + int(length)
	if !isInitial {
		return end, nil // 0-RTT or Handshake coalesced after the Initial
	}
	if p+4+16 > end {
		return 0, errNotInitial
	}
	k, err := q.initialKeys(v, dcid)
	if err != nil {
		return 0, err
	}
	// Remove header protection (RFC 9001 §5.4).
	var mask [aes.BlockSize]byte
	k.hp.Encrypt(mask[:], b[p+4:p+4+16])
	first := b[0] ^ mask[0]&0x0f
	pnLen := int(first&3) + 1
	header := make([]byte, p+pnLen)
	copy(header, b[:p+pnLen])
	header[0] = first
	var pn uint64
	for i := 0; i < pnLen; i++ {
		header[p+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[p+i])
	}
	// The client's first Initial packets have small numbers, so the
	// truncated number is the full one.
	nonce := make([]byte, len(k.iv))
	copy(nonce, k.iv)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := k.aead.Open(nil, nonce, b[p+pnLen:end], header)
	if err != nil {
		return 0, err
	}
	if err := q.frames(plain); err != nil {
		return 0, err
	}
	return end, nil
}

func (q *QUIC) initialKeys(v quicVersion, dcid []byte) (*initialKeys, error) {
	if k, ok := q.keys[string(dcid)]; ok {
		return k, nil
	}
	initial, err := hkdf.Extract(sha256.New, dcid, v.salt)
	if err != nil {
		return nil, err
	}
	client, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := expandLabel(client, v.keyLabel, 16)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabel(client, v.ivLabel, 12)
	if err != nil {
		return nil, err
	}
	hpKey, err := expandLabel(client, v.hpLabel, 16)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hp, err := aes.NewCipher(hpKey)
	if err != nil {
		return nil, err
	}
	k := &initialKeys{aead: aead, iv: iv, hp: hp}
	if q.keys == nil {
		q.keys = map[string]*initialKeys{}
	}
	q.keys[string(dcid)] = k
	return k, nil
}

// expandLabel is HKDF-Expand-Label from TLS 1.3 (RFC 8446 §7.1) with an
// empty context.
func expandLabel(secret []byte, label string, length int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0) // context
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

// frames collects CRYPTO frames from an Initial packet's payload (RFC 9000
// §19); the frames allowed there are PADDING, PING, ACK, CRYPTO and
// CONNECTION_CLOSE.
func (q *QUIC) frames(b []byte) error {
	for len(b) > 0 {
		typ := b[0]
		b = b[1:]
		switch typ {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK
			fields := 4 // largest, delay, range count, first range
			count := uint64(0)
			for i := 0; i < fields; i++ {
				v, n := varint(b)
				if n == 0 {
					return errNotInitial
				}
				if i == 2 {
					count = v
				}
				b = b[n:]
			}
			extra := 2 * count
			if typ == 0x03 {
				extra += 3 // ECN counts
			}
			for i := uint64(0); i < extra; i++ {
				_, n := varint(b)
				if n == 0 {
					return errNotInitial
				}
				b = b[n:]
			}
		case 0x06: // CRYPTO
			off, n := varint(b)
			if n == 0 {
				return errNotInitial
			}
			b = b[n:]
			l, n := varint(b)
			if n == 0 || uint64(len(b)-n) < l {
				return errNotInitial
			}
			b = b[n:]
			if off+l > maxQUICCrypto {
				return errNotInitial
			}
			if q.frags == nil {
				q.frags = map[uint64][]byte{}
			}
			if _, dup := q.frags[off]; !dup {
				q.frags[off] = append([]byte(nil), b[:l]...)
				q.total += int(l)
			}
			b = b[l:]
		default: // CONNECTION_CLOSE or anything else: stop here
			return nil
		}
	}
	return nil
}

// clientHello returns the ClientHello handshake message once the CRYPTO
// stream holds all of it from offset 0.
func (q *QUIC) clientHello() ([]byte, bool) {
	var stream []byte
	for {
		// Fragments may overlap; take any that starts inside what we have.
		progressed := false
		for off, data := range q.frags {
			if off <= uint64(len(stream)) && off+uint64(len(data)) > uint64(len(stream)) {
				stream = append(stream, data[uint64(len(stream))-off:]...)
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	if len(stream) < 4 || stream[0] != 1 { // client_hello
		return nil, false
	}
	n := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if len(stream) < 4+n {
		return nil, false
	}
	return stream[:4+n], true
}

// varint decodes a QUIC variable-length integer (RFC 9000 §16); n is 0 if b
// is too short.
func varint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
