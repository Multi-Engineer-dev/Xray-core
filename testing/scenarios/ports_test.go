package scenarios

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
)

// Some inbounds bind both transports, even when a case sends only UDP.
// Probe both together so an unrelated TCP listener cannot occupy a UDP-picked
// port. As with PickPort, callers must bind promptly after these sockets close.
func pickTCPUDPPort(t *testing.T) net.Port {
	t.Helper()
	for range 32 {
		tcp, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP(), Port: port})
		if err == nil {
			udp.Close()
			tcp.Close()
			return net.Port(port)
		}
		tcp.Close()
	}
	t.Fatal("could not find a port available for both TCP and UDP")
	return 0
}
