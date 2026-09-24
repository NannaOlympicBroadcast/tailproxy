// Package sniff reads the destination host name from the first bytes a
// client sends (DESIGN §4.2, §4.7): the server_name of a TLS ClientHello or
// the Host header of an HTTP/1 request. Nothing is decrypted; the bytes read
// are replayed to the real destination unchanged.
package sniff

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Result is what sniffing found.
type Result struct {
	Protocol string // "tls", "http" or "" when neither was recognised
	Host     string // lower-case, without port or trailing dot; "" if absent
	// ECH is set when the ClientHello carries an encrypted_client_hello
	// extension: Host is then only the outer (public) name, which may not
	// be the real site (DESIGN §4.7).
	ECH bool
}

// maxPeek bounds how much is buffered while sniffing. A ClientHello with
// post-quantum key shares is a few KB; a TLS record is at most 16 KB + 5.
const maxPeek = 16384 + 5

// Conn replays the sniffed bytes before reading from the connection.
type Conn struct {
	net.Conn
	r *bufio.Reader
}

func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the underlying connection when it supports it.
func (c *Conn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// Peek waits up to timeout for the client's first bytes and sniffs them. It
// returns a Conn that yields every byte the client sent, including those
// read here. A client that sends nothing first (e.g. SMTP, SSH) simply
// yields an empty Result after the timeout.
func Peek(c net.Conn, timeout time.Duration) (Result, *Conn) {
	br := bufio.NewReaderSize(c, maxPeek)
	out := &Conn{Conn: c, r: br}
	c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	first, err := br.Peek(1)
	if err != nil || len(first) == 0 {
		return Result{}, out
	}
	switch {
	case first[0] == 0x16: // TLS handshake record
		return sniffTLS(br), out
	case first[0] >= 'A' && first[0] <= 'Z':
		return sniffHTTP(br), out
	}
	return Result{}, out
}

// peekAtLeast returns at least n buffered bytes, reading more if needed.
func peekAtLeast(br *bufio.Reader, n int) ([]byte, error) {
	if n > maxPeek {
		return nil, errors.New("too long")
	}
	return br.Peek(n)
}

func sniffTLS(br *bufio.Reader) Result {
	res := Result{Protocol: "tls"}
	hdr, err := peekAtLeast(br, 5)
	if err != nil {
		return Result{}
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if hdr[1] != 3 || recLen < 4 {
		return Result{}
	}
	rec, err := peekAtLeast(br, 5+recLen)
	if err != nil {
		// Take what arrived; a ClientHello split across records is rare
		// and its SNI usually sits in the first one anyway.
		rec, _ = br.Peek(br.Buffered())
	}
	host, ech, ok := parseClientHello(rec[5:])
	if !ok {
		return res
	}
	res.Host, res.ECH = normalize(host), ech
	return res
}

// parseClientHello extracts server_name and the presence of the ECH
// extension from a handshake message (RFC 8446 §4.1.2, RFC 6066 §3).
func parseClientHello(b []byte) (host string, ech bool, ok bool) {
	if len(b) < 4 || b[0] != 1 { // client_hello
		return "", false, false
	}
	b = b[4:] // type + uint24 length; tolerate truncation below
	if len(b) < 2+32+1 {
		return "", false, false
	}
	b = b[2+32:] // legacy_version, random
	sidLen := int(b[0])
	if len(b) < 1+sidLen+2 {
		return "", false, false
	}
	b = b[1+sidLen:]
	csLen := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+csLen+1 {
		return "", false, false
	}
	b = b[2+csLen:]
	cmLen := int(b[0])
	if len(b) < 1+cmLen+2 {
		return "", false, false
	}
	b = b[1+cmLen:]
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if extLen < len(b) {
		b = b[:extLen]
	}
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			break
		}
		data := b[4 : 4+l]
		b = b[4+l:]
		switch typ {
		case 0x0000: // server_name
			if h, ok := parseServerName(data); ok {
				host = h
			}
		case 0xfe0d: // encrypted_client_hello (RFC 9849)
			ech = true
		}
	}
	return host, ech, true
}

func parseServerName(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	b = b[2:] // server_name_list length
	for len(b) >= 3 {
		typ := b[0]
		l := int(binary.BigEndian.Uint16(b[1:]))
		if len(b) < 3+l {
			return "", false
		}
		if typ == 0 { // host_name
			return string(b[3 : 3+l]), true
		}
		b = b[3+l:]
	}
	return "", false
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

func sniffHTTP(br *bufio.Reader) Result {
	// Use what has arrived; wait for more only while the headers are
	// incomplete, so a short request never waits for the timeout.
	buf, _ := br.Peek(br.Buffered())
	for !bytes.Contains(buf, []byte("\r\n\r\n")) && len(buf) < 4096 {
		if _, err := br.Peek(len(buf) + 1); err != nil {
			break
		}
		buf, _ = br.Peek(min(br.Buffered(), 4096))
	}
	s := string(buf)
	isHTTP := false
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return Result{}
	}
	res := Result{Protocol: "http"}
	lines := strings.Split(s, "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			res.Host = normalize(strings.TrimSpace(v))
			break
		}
	}
	return res
}

// normalize lower-cases h and strips a port and trailing dot. IP literals
// are dropped: they add nothing to what the connection already knows.
func normalize(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	if len(h) > 253 || strings.ContainsAny(h, " /\\\x00") {
		return ""
	}
	return h
}

var _ io.Reader = (*Conn)(nil)
