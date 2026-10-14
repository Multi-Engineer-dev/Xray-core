package wireguard

import (
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func newTestNetTun(t *testing.T) (*netTun, net.Conn) {
	t.Helper()
	dev, tnet, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil, 1420, true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	return dev.(*netTun), c
}

func testBufs(n int) ([][]byte, []int) {
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	return bufs, make([]int, n)
}

// Packets the stack sends wait in the endpoint queue and come out of one
// Read together, so wireguard-go can handle them as a batch.
func TestNetTunReadBatch(t *testing.T) {
	tun, c := newTestNetTun(t)
	defer tun.Close()
	const count = 5
	for i := 0; i < count; i++ {
		if _, err := c.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	const offset = 16
	bufs, sizes := testBufs(8)
	n, err := tun.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatal(err)
	}
	if n != count {
		t.Fatalf("read %d packets, want %d", n, count)
	}
	for i := 0; i < n; i++ {
		ip := header.IPv4(bufs[i][offset : offset+sizes[i]])
		if !ip.IsValid(sizes[i]) || ip.TransportProtocol() != header.UDPProtocolNumber {
			t.Fatalf("packet %d is not an IPv4 UDP packet", i)
		}
		if p := header.UDP(ip.Payload()).Payload(); len(p) != 1 || p[0] != byte(i) {
			t.Fatalf("packet %d carries %v, want [%d]", i, p, i)
		}
	}
}

// A sender waits once maxQueued packets are queued instead of overflowing
// the endpoint queue, and goes on when Read takes them or the tun closes.
func TestNetTunBackpressure(t *testing.T) {
	for _, closeTun := range []bool{false, true} {
		tun, c := newTestNetTun(t)
		const count = maxQueued + 10
		done := make(chan struct{})
		go func() {
			for i := 0; i < count; i++ {
				_, _ = c.Write([]byte{byte(i)})
			}
			close(done)
		}()
		time.Sleep(200 * time.Millisecond)
		select {
		case <-done:
			t.Fatal("sender did not wait for the reader")
		default:
		}
		if n := tun.ep.NumQueued(); n != maxQueued {
			t.Fatalf("%d packets queued, want %d", n, maxQueued)
		}
		if closeTun {
			tun.Close()
		} else {
			defer tun.Close()
			bufs, sizes := testBufs(128)
			for got := 0; got < count; {
				n, err := tun.Read(bufs, sizes, 0)
				if err != nil {
					t.Fatal(err)
				}
				got += n
			}
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("sender still waiting (close: %v)", closeTun)
		}
	}
}
