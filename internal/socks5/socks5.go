// Package socks5 implements the parts of SOCKS5 (RFC 1928) tailproxy uses:
// CONNECT, with either no authentication or username/password (RFC 1929),
// on both the server and the client side, and on the server side UDP
// ASSOCIATE (§7, without fragmentation).
package socks5

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
)

const (
	version     = 5
	authVersion = 1

	MethodNoAuth   = 0x00
	MethodUserPass = 0x02
	methodNone     = 0xFF

	CmdConnect      = 1
	CmdUDPAssociate = 3

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	RepSucceeded        = 0
	RepGeneralFailure   = 1
	RepNotAllowed       = 2
	RepNetUnreachable   = 3
	RepHostUnreachable  = 4
	RepConnRefused      = 5
	RepCmdNotSupported  = 7
	RepAtypNotSupported = 8
)

// ErrAuthFailed is returned by the server handshake for a wrong password and
// by the client when the server rejects the credentials.
var ErrAuthFailed = errors.New("socks5: authentication failed")

// Credentials, when non-nil, makes the server require username/password auth.
type Credentials struct {
	User     string
	Password string
}

func (c *Credentials) match(user, pass string) bool {
	return subtle.ConstantTimeCompare([]byte(user), []byte(c.User)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(c.Password)) == 1
}

// Request is a client's request after the method negotiation.
type Request struct {
	Cmd  byte
	Host string // IP literal or domain; may be empty for UDP ASSOCIATE
	Port uint16
}

// ServerHandshake negotiates the method (no-auth, or username/password when
// creds is set), reads a CONNECT request and returns its destination.
// Unsupported requests get an error reply before an error is returned.
func ServerHandshake(rw io.ReadWriter, creds *Credentials) (host string, port uint16, err error) {
	req, err := ServerRequest(rw, creds, CmdConnect)
	return req.Host, req.Port, err
}

// ServerRequest is ServerHandshake for any of the commands in cmds. For UDP
// ASSOCIATE the address is where the client will send from, often
// 0.0.0.0:0 (unknown).
func ServerRequest(rw io.ReadWriter, creds *Credentials, cmds ...byte) (req Request, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(rw, hdr[:]); err != nil {
		return
	}
	if hdr[0] != version {
		return req, fmt.Errorf("not SOCKS5 (version %d)", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(rw, methods); err != nil {
		return
	}
	want := byte(MethodNoAuth)
	if creds != nil {
		want = MethodUserPass
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == want
	}
	if !offered {
		rw.Write([]byte{version, methodNone})
		return req, fmt.Errorf("client does not offer method %d", want)
	}
	if _, err = rw.Write([]byte{version, want}); err != nil {
		return
	}
	if creds != nil {
		if err = serverAuth(rw, creds); err != nil {
			return
		}
	}

	var h [4]byte
	if _, err = io.ReadFull(rw, h[:]); err != nil {
		return
	}
	if h[0] != version {
		return req, fmt.Errorf("bad request version %d", h[0])
	}
	req.Cmd = h[1]
	if req.Host, err = readAddr(rw, h[3]); err != nil {
		if errors.Is(err, errAtyp) {
			WriteReply(rw, RepAtypNotSupported, netip.AddrPort{})
		}
		return
	}
	var p [2]byte
	if _, err = io.ReadFull(rw, p[:]); err != nil {
		return
	}
	req.Port = binary.BigEndian.Uint16(p[:])
	if !slices.Contains(cmds, req.Cmd) {
		WriteReply(rw, RepCmdNotSupported, netip.AddrPort{})
		return req, fmt.Errorf("command %d not supported", req.Cmd)
	}
	if req.Cmd == CmdConnect && req.Host == "" {
		WriteReply(rw, RepGeneralFailure, netip.AddrPort{})
		return req, errors.New("empty host")
	}
	return req, nil
}

func serverAuth(rw io.ReadWriter, creds *Credentials) error {
	var h [2]byte
	if _, err := io.ReadFull(rw, h[:]); err != nil {
		return err
	}
	if h[0] != authVersion {
		return fmt.Errorf("bad auth version %d", h[0])
	}
	user := make([]byte, h[1])
	if _, err := io.ReadFull(rw, user); err != nil {
		return err
	}
	var pl [1]byte
	if _, err := io.ReadFull(rw, pl[:]); err != nil {
		return err
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(rw, pass); err != nil {
		return err
	}
	if !creds.match(string(user), string(pass)) {
		rw.Write([]byte{authVersion, 1})
		return ErrAuthFailed
	}
	_, err := rw.Write([]byte{authVersion, 0})
	return err
}

var errAtyp = errors.New("address type not supported")

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom4(b).String(), nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		return netip.AddrFrom16(b).Unmap().String(), nil
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("%w: %d", errAtyp, atyp)
}

// WriteReply sends a CONNECT reply; bound may be the zero value.
func WriteReply(w io.Writer, code byte, bound netip.AddrPort) error {
	b := []byte{version, code, 0}
	a := bound.Addr().Unmap()
	switch {
	case a.Is4():
		v := a.As4()
		b = append(b, atypIPv4)
		b = append(b, v[:]...)
	case a.Is6():
		v := a.As16()
		b = append(b, atypIPv6)
		b = append(b, v[:]...)
	default:
		b = append(b, atypIPv4, 0, 0, 0, 0)
	}
	b = binary.BigEndian.AppendUint16(b, bound.Port())
	_, err := w.Write(b)
	return err
}

// ReplyError is a non-success CONNECT reply received by the client.
type ReplyError struct{ Code byte }

func (e *ReplyError) Error() string {
	msg := map[byte]string{
		RepGeneralFailure: "general failure", RepNotAllowed: "not allowed by the relay",
		RepNetUnreachable: "network unreachable", RepHostUnreachable: "host unreachable",
		RepConnRefused: "connection refused", RepCmdNotSupported: "command not supported",
		RepAtypNotSupported: "address type not supported",
	}[e.Code]
	if msg == "" {
		msg = fmt.Sprintf("reply code %d", e.Code)
	}
	return "socks5 relay: " + msg
}

// ClientAuth runs the client side of method negotiation and, with creds,
// username/password authentication. It does not send a request, so it is
// also a cheap way to check that a server is up and accepts the credentials.
func ClientAuth(rw io.ReadWriter, creds *Credentials) error {
	method := byte(MethodNoAuth)
	if creds != nil {
		method = MethodUserPass
	}
	if _, err := rw.Write([]byte{version, 1, method}); err != nil {
		return err
	}
	var r [2]byte
	if _, err := io.ReadFull(rw, r[:]); err != nil {
		return err
	}
	if r[0] != version || r[1] != method {
		if r[1] == methodNone {
			return fmt.Errorf("socks5: server refused method %d", method)
		}
		return fmt.Errorf("socks5: unexpected method reply %v", r)
	}
	if creds == nil {
		return nil
	}
	if len(creds.User) > 255 || len(creds.Password) > 255 {
		return errors.New("socks5: credentials too long")
	}
	b := []byte{authVersion, byte(len(creds.User))}
	b = append(b, creds.User...)
	b = append(b, byte(len(creds.Password)))
	b = append(b, creds.Password...)
	if _, err := rw.Write(b); err != nil {
		return err
	}
	if _, err := io.ReadFull(rw, r[:]); err != nil {
		return err
	}
	if r[1] != 0 {
		return ErrAuthFailed
	}
	return nil
}

// ClientConnect authenticates (see ClientAuth) and asks the server to connect
// to host:port. Domain names are sent as names, so the server resolves them.
func ClientConnect(rw io.ReadWriter, creds *Credentials, host string, port uint16) error {
	if err := ClientAuth(rw, creds); err != nil {
		return err
	}
	b := []byte{version, CmdConnect, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append(b, atypIPv4)
			b = append(b, v[:]...)
		} else {
			v := ip.As16()
			b = append(b, atypIPv6)
			b = append(b, v[:]...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks5: host name too long")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	b = binary.BigEndian.AppendUint16(b, port)
	if _, err := rw.Write(b); err != nil {
		return err
	}
	var h [4]byte
	if _, err := io.ReadFull(rw, h[:]); err != nil {
		return err
	}
	if _, err := readAddr(rw, h[3]); err != nil {
		return err
	}
	var p [2]byte
	if _, err := io.ReadFull(rw, p[:]); err != nil {
		return err
	}
	if h[1] != RepSucceeded {
		return &ReplyError{Code: h[1]}
	}
	return nil
}
