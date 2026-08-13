package shadowsocks

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/proxy"

	sscipher "github.com/sagernet/sing-shadowsocks2/cipher"
	"github.com/sagernet/sing-shadowsocks2/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

var ss2022Ciphers = map[string]struct{}{
	"2022-blake3-aes-128-gcm":       {},
	"2022-blake3-aes-256-gcm":       {},
	"2022-blake3-chacha20-poly1305": {},
}

func isSS2022Cipher(cipher string) bool {
	_, ok := ss2022Ciphers[cipher]
	return ok
}

type ss2022Dialer struct {
	nextDialer   proxy.Dialer
	proxyAddress string
	method       sscipher.Method
}

func newSS2022Dialer(nextDialer proxy.Dialer, proxyAddress, cipherName, password string) (proxy.Dialer, error) {
	method, err := shadowaead_2022.NewMethod(context.Background(), cipherName, sscipher.MethodOptions{
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return &ss2022Dialer{
		nextDialer:   nextDialer,
		proxyAddress: proxyAddress,
		method:       method,
	}, nil
}

func (d *ss2022Dialer) Dial(network, addr string) (net.Conn, error) {
	destination := M.ParseSocksaddr(addr)
	if !destination.IsValid() || destination.Port == 0 {
		return nil, fmt.Errorf("invalid target address: %v", addr)
	}
	switch network {
	case "tcp":
		conn, err := d.nextDialer.Dial("tcp", d.proxyAddress)
		if err != nil {
			return nil, err
		}
		ssConn, err := d.method.DialConn(conn, destination)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return ssConn, nil
	case "udp":
		conn, err := d.nextDialer.Dial("udp", d.proxyAddress)
		if err != nil {
			return nil, err
		}
		return &ss2022PacketConn{
			PacketConn: d.method.DialPacketConn(conn),
			remoteAddr: conn.RemoteAddr(),
			writeAddr:  destination,
		}, nil
	default:
		return nil, net.UnknownNetworkError(network)
	}
}

type ss2022PacketConn struct {
	net.PacketConn
	remoteAddr net.Addr
	writeAddr  net.Addr
}

func (c *ss2022PacketConn) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *ss2022PacketConn) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.writeAddr)
}

func (c *ss2022PacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}
