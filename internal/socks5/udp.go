package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// UDP ASSOCIATE datagrams (RFC 1928 §7) carry a header before the data:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+

// ErrFragment is returned for a datagram with a non-zero FRAG field; an
// implementation without reassembly must drop those (§7).
var ErrFragment = errors.New("socks5: fragmented UDP datagram")

// ParseUDP splits a client's datagram into its destination and data. The
// data aliases b.
func ParseUDP(b []byte) (host string, port uint16, data []byte, err error) {
	if len(b) < 4 {
		return "", 0, nil, errors.New("socks5: short UDP datagram")
	}
	if b[2] != 0 {
		return "", 0, nil, ErrFragment
	}
	r := bytes.NewReader(b[4:])
	if host, err = readAddr(r, b[3]); err != nil {
		if !errors.Is(err, errAtyp) {
			err = errors.New("socks5: short UDP datagram")
		}
		return "", 0, nil, err
	}
	var p [2]byte
	if _, err = io.ReadFull(r, p[:]); err != nil {
		return "", 0, nil, errors.New("socks5: short UDP datagram")
	}
	if host == "" {
		return "", 0, nil, errors.New("socks5: empty UDP destination")
	}
	off := len(b) - r.Len()
	return host, binary.BigEndian.Uint16(p[:]), b[off:], nil
}

// AppendUDPHeader appends the header of a datagram from host:port (an IP
// literal or a domain) to b.
func AppendUDPHeader(b []byte, host string, port uint16) []byte {
	b = append(b, 0, 0, 0)
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append(append(b, atypIPv4), v[:]...)
		} else {
			v := ip.As16()
			b = append(append(b, atypIPv6), v[:]...)
		}
	} else {
		b = append(append(b, atypDomain, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}
