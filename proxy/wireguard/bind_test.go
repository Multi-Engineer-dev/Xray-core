package wireguard

import (
	"bytes"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type testCounter struct{ v atomic.Int64 }

func (c *testCounter) Value() int64      { return c.v.Load() }
func (c *testCounter) Set(n int64) int64 { return c.v.Swap(n) }
func (c *testCounter) Add(n int64) int64 { return c.v.Add(n) - n }

// openTestBind opens a bind on a loopback UDP socket wrapped like client.go
// does when stats are enabled.
func openTestBind(t *testing.T, network, addr string, reserved []byte) (*bind, conn.ReceiveFunc, *testCounter, *testCounter) {
	t.Helper()
	rc, wc := &testCounter{}, &testCounter{}
	b := &bind{
		reserved: reserved,
		listenFunc: func() (net.PacketConn, error) {
			c, err := net.ListenPacket(network, addr)
			if err != nil {
				return nil, err
			}
			return &PacketCounterConnection{PacketConn: c, ReadCounter: rc, WriteCounter: wc}, nil
		},
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, fns[0], rc, wc
}

func testPacket(i int) []byte {
	p := make([]byte, 100+i)
	p[0] = 4
	for j := 4; j < len(p); j++ {
		p[j] = byte(i)
	}
	return p
}

func testBindRoundTrip(t *testing.T, network, bindAddr, peerAddr string, wantBatch bool) {
	b, recv, rc, wc := openTestBind(t, network, bindAddr, []byte{1, 2, 3})
	if (b.batch != nil) != wantBatch {
		t.Fatalf("batch = %v, want %v", b.batch != nil, wantBatch)
	}
	peer, err := net.ListenPacket("udp", peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerAP := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	// Send: every datagram arrives intact, with the reserved bytes set.
	const count = 200 // more than conn.IdealBatchSize
	bufs := make([][]byte, count)
	var total int64
	for i := range bufs {
		bufs[i] = testPacket(i % 50)
		total += int64(len(bufs[i]))
	}
	if err := b.Send(bufs, &conn.StdNetEndpoint{AddrPort: peerAP}); err != nil {
		t.Fatal(err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < count; i++ {
		n, _, err := peer.ReadFrom(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		want := testPacket(i % 50)
		copy(want[1:4], []byte{1, 2, 3})
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d differs", i)
		}
	}
	if wc.Value() != total {
		t.Fatalf("write counter = %d, want %d", wc.Value(), total)
	}

	// Receive: datagrams come back with the reserved bytes cleared and the
	// peer as endpoint.
	bindAP := netip.AddrPortFrom(peerAP.Addr(), uint16(b.LocalAddr().(*net.UDPAddr).Port))
	total = 0
	for i := 0; i < count; i++ {
		p := testPacket(i % 50)
		copy(p[1:4], []byte{9, 9, 9})
		total += int64(len(p))
		if _, err := peer.WriteTo(p, net.UDPAddrFromAddrPort(bindAP)); err != nil {
			t.Fatal(err)
		}
	}
	rbufs := make([][]byte, conn.IdealBatchSize)
	for i := range rbufs {
		rbufs[i] = make([]byte, 2048)
	}
	sizes := make([]int, len(rbufs))
	eps := make([]conn.Endpoint, len(rbufs))
	got := 0
	for got < count {
		n, err := recv(rbufs, sizes, eps)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			want := testPacket((got + i) % 50)
			if !bytes.Equal(rbufs[i][:sizes[i]], want) {
				t.Fatalf("received datagram %d differs", got+i)
			}
			ep := eps[i].(*conn.StdNetEndpoint).AddrPort
			if ep.Addr().Unmap() != peerAP.Addr().Unmap() || ep.Port() != peerAP.Port() {
				t.Fatalf("endpoint = %v, want %v", ep, peerAP)
			}
		}
		got += n
	}
	if rc.Value() != total {
		t.Fatalf("read counter = %d, want %d", rc.Value(), total)
	}

	// Close ends a pending receive with net.ErrClosed.
	done := make(chan error, 1)
	go func() {
		_, err := recv(rbufs, sizes, eps)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = b.Close()
	select {
	case err := <-done:
		if err != net.ErrClosed {
			t.Fatalf("receive after close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return after close")
	}
}

func TestBindIPv4(t *testing.T) {
	testBindRoundTrip(t, "udp4", "127.0.0.1:0", "127.0.0.1:0", batchSize > 1)
}

// Xray's dialer listens on a dual-stack socket and sends to IPv4 peers.
func TestBindDualStackToIPv4(t *testing.T) {
	testBindRoundTrip(t, "udp", "[::]:0", "127.0.0.1:0", batchSize > 1)
}

func TestBindIPv6(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no IPv6 loopback")
	} else {
		c.Close()
	}
	testBindRoundTrip(t, "udp6", "[::1]:0", "[::1]:0", batchSize > 1)
}
