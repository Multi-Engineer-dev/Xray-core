package wireguard

import (
	"context"
	goerrors "errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

// socketBufferSize matches wireguard-go's StdNetBind.
const socketBufferSize = 7 << 20

// batchConn reads and writes many datagrams per syscall (recvmmsg/sendmmsg).
// ipv4.PacketConn and ipv6.PacketConn both implement it.
type batchConn interface {
	ReadBatch(ms []ipv6.Message, flags int) (int, error)
	WriteBatch(ms []ipv6.Message, flags int) (int, error)
}

type bind struct {
	resolveFunc func(host string) (net.IP, error)
	listenFunc  func() (net.PacketConn, error)
	downFunc    func() error
	reserved    []byte

	net.PacketConn
	// batch is set when the conn is a plain UDP socket on Linux. The traffic
	// counters are then applied here, since PacketCounterConnection is bypassed.
	batch        batchConn
	readCounter  stats.Counter
	writeCounter stats.Counter
	msgsPool     sync.Pool
	closeCh      chan struct{}
	mu           sync.Mutex
}

func (b *bind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.PacketConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	c, err := b.listenFunc()
	if err != nil {
		return nil, 0, err
	}
	b.PacketConn = c
	b.batch, b.readCounter, b.writeCounter = newBatchConn(c)
	ch := make(chan struct{})
	b.closeCh = ch

	recv := b.makeReceive(c, ch)
	if b.batch != nil {
		recv = b.makeReceiveBatch(b.batch, ch)
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

// readFailed handles a read error and reports whether the bind is closed.
func (b *bind) readFailed(err error, ch chan struct{}) bool {
	if goerrors.Is(err, io.EOF) || goerrors.Is(err, io.ErrClosedPipe) || goerrors.Is(err, net.ErrClosed) {
		select {
		case <-ch:
		default:
			errors.LogErrorInner(context.Background(), err, "unexpected closed")
			b.mu.Lock()
			downFunc := b.downFunc
			b.mu.Unlock()
			if downFunc != nil {
				go func() {
					common.Must(downFunc())
				}()
			}
		}
		return true
	}
	errors.LogErrorInner(context.Background(), err, "bind recv err")
	return false
}

func (b *bind) makeReceive(c net.PacketConn, ch chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (n int, err error) {
		for {
			n, addr, err := c.ReadFrom(bufs[0])
			if err != nil {
				if b.readFailed(err, ch) {
					return 0, net.ErrClosed
				}
				continue
			}
			if n > 3 {
				bufs[0][1] = 0
				bufs[0][2] = 0
				bufs[0][3] = 0
			}
			sizes[0] = n
			eps[0] = &conn.StdNetEndpoint{AddrPort: addr.(*net.UDPAddr).AddrPort()}
			return 1, nil
		}
	}
}

// makeReceiveBatch reads up to len(bufs) datagrams per call. wireguard-go calls
// each ReceiveFunc from a single goroutine, so msgs is not shared.
func (b *bind) makeReceiveBatch(bc batchConn, ch chan struct{}) conn.ReceiveFunc {
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
	}
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		count := min(len(bufs), len(msgs))
		for i := 0; i < count; i++ {
			msgs[i].Buffers[0] = bufs[i]
			msgs[i].N = 0
			msgs[i].Addr = nil
		}
		for {
			n, err := bc.ReadBatch(msgs[:count], 0)
			if err != nil {
				if b.readFailed(err, ch) {
					return 0, net.ErrClosed
				}
				continue
			}
			var total int64
			for i := 0; i < n; i++ {
				m := &msgs[i]
				if m.N > 3 {
					bufs[i][1] = 0
					bufs[i][2] = 0
					bufs[i][3] = 0
				}
				sizes[i] = m.N
				eps[i] = &conn.StdNetEndpoint{AddrPort: m.Addr.(*net.UDPAddr).AddrPort()}
				total += int64(m.N)
			}
			if b.readCounter != nil {
				b.readCounter.Add(total)
			}
			return n, nil
		}
	}
}

// setDownFunc sets downFunc after the device is created, since the device may already be using the bind.
func (b *bind) setDownFunc(f func() error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.downFunc = f
}

func (b *bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.PacketConn != nil {
		close(b.closeCh)
		_ = b.PacketConn.Close()
		b.PacketConn = nil
		b.batch = nil
	}
	return nil
}

func (b *bind) SetMark(mark uint32) error {
	return nil
}

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c, bc, wc := b.PacketConn, b.batch, b.writeCounter
	b.mu.Unlock()

	if c == nil {
		return syscall.EAFNOSUPPORT
	}

	if len(b.reserved) == 3 {
		for i := range bufs {
			if len(bufs[i]) > 3 {
				bufs[i][1] = b.reserved[0]
				bufs[i][2] = b.reserved[1]
				bufs[i][3] = b.reserved[2]
			}
		}
	}
	addr := net.UDPAddrFromAddrPort(ep.(*conn.StdNetEndpoint).AddrPort)

	if bc == nil {
		for i := range bufs {
			if _, err := c.WriteTo(bufs[i], addr); err != nil {
				errors.LogErrorInner(context.Background(), err, "bind send err")
				return err
			}
		}
		return nil
	}

	msgs := b.getMsgs()
	defer b.putMsgs(msgs)
	sent, err := sendBatch(bc, *msgs, bufs, addr)
	if wc != nil {
		var total int64
		for _, buf := range bufs[:sent] {
			total += int64(len(buf))
		}
		wc.Add(total)
	}
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "bind send err")
	}
	return err
}

// sendBatch sends bufs to addr and returns how many of them went out before
// an error.
func sendBatch(bc batchConn, msgs []ipv6.Message, bufs [][]byte, addr *net.UDPAddr) (int, error) {
	sent := 0
	for sent < len(bufs) {
		n := min(len(bufs)-sent, len(msgs))
		for i := 0; i < n; i++ {
			msgs[i].Buffers = bufs[sent+i : sent+i+1]
			msgs[i].Addr = addr
		}
		for i := 0; i < n; {
			k, err := bc.WriteBatch(msgs[i:n], 0)
			if err != nil {
				return sent + i, err
			}
			i += k
		}
		sent += n
	}
	return sent, nil
}

func (b *bind) getMsgs() *[]ipv6.Message {
	if m, ok := b.msgsPool.Get().(*[]ipv6.Message); ok {
		return m
	}
	msgs := make([]ipv6.Message, conn.IdealBatchSize)
	return &msgs
}

func (b *bind) putMsgs(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].Buffers = nil
		(*msgs)[i].Addr = nil
	}
	b.msgsPool.Put(msgs)
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	if b.resolveFunc == nil {
		e, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, err
		}
		return &conn.StdNetEndpoint{
			AddrPort: e,
		}, nil
	}
	host, sport, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(sport)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port " + sport)
	}
	ip, err := b.resolveFunc(host)
	if err != nil {
		return nil, err
	}
	addr, _ := netip.AddrFromSlice(ip)
	return &conn.StdNetEndpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
	}, nil
}

func (b *bind) BatchSize() int {
	return batchSize
}
