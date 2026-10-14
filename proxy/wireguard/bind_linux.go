//go:build linux

package wireguard

import (
	"net"

	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const batchSize = conn.IdealBatchSize

// newBatchConn returns a batchConn for c, or nil when c is not a plain UDP
// socket.
func newBatchConn(c net.PacketConn) (bc batchConn, rc, wc stats.Counter) {
	if pc, ok := c.(*PacketCounterConnection); ok {
		c, rc, wc = pc.PacketConn, pc.ReadCounter, pc.WriteCounter
	}
	udp, ok := c.(*net.UDPConn)
	if !ok {
		return nil, nil, nil
	}
	setSocketBuffers(udp)
	if la, ok := udp.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		return ipv4.NewPacketConn(udp), rc, wc
	}
	return ipv6.NewPacketConn(udp), rc, wc
}

// setSocketBuffers raises the UDP socket buffers like wireguard-go does. The
// FORCE variants pass net.core.rmem_max/wmem_max but need CAP_NET_ADMIN, so
// they fail quietly without it.
func setSocketBuffers(c *net.UDPConn) {
	_ = c.SetReadBuffer(socketBufferSize)
	_ = c.SetWriteBuffer(socketBufferSize)
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, socketBufferSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, socketBufferSize)
	})
}
