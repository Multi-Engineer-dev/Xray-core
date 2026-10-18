package wireguard

import (
	"bytes"
	"net/netip"
	"testing"
)

// Read takes what is already queued in one call, up to len(bufs) and at offset,
// as the WireGuard device sends a read in one batch, and it does not wait for more.
func TestNetTUNReadBatch(t *testing.T) {
	dev, _, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.2")}, nil, 1420, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	for i := range 5 {
		if err := dev.(*netTun).WritePacket([]byte{byte(i), 1}, []byte{2, byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	const offset = 16
	bufs, sizes := make([][]byte, 3), make([]int, 3)
	for i := range bufs {
		bufs[i] = make([]byte, offset+8)
	}
	next := 0
	for _, want := range []int{3, 2} {
		n, err := dev.Read(bufs, sizes, offset)
		if err != nil || n != want {
			t.Fatalf("read %d packets, want %d, error: %v", n, want, err)
		}
		for i := range n {
			if got := bufs[i][offset : offset+sizes[i]]; !bytes.Equal(got, []byte{byte(next), 1, 2, byte(next)}) {
				t.Fatalf("read %v of packet %d", got, next)
			}
			next++
		}
	}
}
