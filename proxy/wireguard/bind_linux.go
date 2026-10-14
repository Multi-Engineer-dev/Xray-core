//go:build linux

package wireguard

import (
	"encoding/binary"
	goerrors "errors"
	"net"
	"unsafe"

	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

const batchSize = conn.IdealBatchSize

var gsoControlSize = unix.CmsgSpace(2)

// newBatchConn returns a batchConn for c, or nil when c is not a plain UDP
// socket. gso reports UDP_SEGMENT support.
func newBatchConn(c net.PacketConn) (bc batchConn, gso bool, rc, wc stats.Counter) {
	if pc, ok := c.(*PacketCounterConnection); ok {
		c, rc, wc = pc.PacketConn, pc.ReadCounter, pc.WriteCounter
	}
	udp, ok := c.(*net.UDPConn)
	if !ok {
		return nil, false, nil, nil
	}
	setSocketBuffers(udp)
	gso = supportsGSO(udp)
	if la, ok := udp.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		return ipv4.NewPacketConn(udp), gso, rc, wc
	}
	return ipv6.NewPacketConn(udp), gso, rc, wc
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

// supportsGSO reports whether the kernel takes UDP_SEGMENT on c (Linux 4.18+).
func supportsGSO(c *net.UDPConn) bool {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	var gso bool
	_ = rc.Control(func(fd uintptr) {
		_, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		gso = err == nil
	})
	return gso
}

// setGSOSize returns oob[:0] holding a UDP_SEGMENT control message.
func setGSOSize(oob []byte, size int) []byte {
	if cap(oob) < gsoControlSize {
		oob = make([]byte, gsoControlSize)
	}
	oob = oob[:gsoControlSize]
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.SOL_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(size))
	return oob
}

// gsoFailed reports whether a send failed because the route cannot take
// UDP_SEGMENT: EIO without checksum offload, EMSGSIZE (EINVAL on older
// kernels) when a segment is larger than the path MTU, where a plain send
// would be fragmented.
func gsoFailed(err error) bool {
	return goerrors.Is(err, unix.EIO) || goerrors.Is(err, unix.EMSGSIZE) || goerrors.Is(err, unix.EINVAL)
}
