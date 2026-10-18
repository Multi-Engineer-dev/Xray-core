package shadowsocks_2022

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type lifecycleConn struct {
	net.Conn
	packet  []byte
	replies chan []byte
}

func (c *lifecycleConn) Read(p []byte) (int, error) {
	if c.packet == nil {
		return 0, io.EOF
	}
	n := copy(p, c.packet)
	c.packet = nil
	return n, nil
}

func (c *lifecycleConn) Write(p []byte) (int, error) {
	c.replies <- append([]byte(nil), p...)
	return len(p), nil
}

func (c *lifecycleConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 12345}
}

type lifecyclePolicy struct {
	policy.Manager
	idle time.Duration
}

func (p lifecyclePolicy) ForLevel(uint32) policy.Session {
	s := policy.SessionDefault()
	s.Timeouts.ConnectionIdle = p.idle
	return s
}

type lifecycleWriter struct{ count atomic.Int32 }

func (w *lifecycleWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.count.Add(int32(len(mb)))
	buf.ReleaseMulti(mb)
	return nil
}

type lifecycleDispatcher struct {
	routing.Dispatcher
	count     atomic.Int32
	writer    lifecycleWriter
	responses *pipe.Writer
	ctx       context.Context
}

func (d *lifecycleDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	d.count.Add(1)
	reader, writer := pipe.New()
	d.responses = writer
	d.ctx = ctx
	return &transport.Link{Reader: reader, Writer: &d.writer}, nil
}

type lifecycleHarness struct {
	client   *ClientUDPSession
	manager  *UDPSessionManager
	dispatch *lifecycleDispatcher
	multi    *MultiUserInbound
	process  func(context.Context, stat.Connection, routing.Dispatcher) error
}

func newLifecycleHarness(t *testing.T, methodName string, multi bool) *lifecycleHarness {
	t.Helper()
	method, err := GetCipherMethod(methodName)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{1}, method.KeySaltLength)
	keys := [][]byte{key}
	h := &lifecycleHarness{dispatch: new(lifecycleDispatcher)}
	user := &protocol.MemoryUser{Email: "test@example.invalid", Account: &MemoryAccount{Key: key}}
	p := lifecyclePolicy{idle: time.Hour}
	if multi {
		master := bytes.Repeat([]byte{2}, method.KeySaltLength)
		keys = [][]byte{master, key}
		block, err := method.NewBlock(master)
		if err != nil {
			t.Fatal(err)
		}
		users := utils.NewTypedSyncMap[[AESBlockSize]byte, *protocol.MemoryUser]()
		users.Store(DeriveUserPSKHash(key), user)
		inbound := &MultiUserInbound{method: method, udpMasterCipher: block, usersByHash: users, udpSessions: NewUDPSessionManager(time.Hour), policyManager: p}
		h.multi = inbound
		h.manager = inbound.udpSessions
		h.process = inbound.processUDP
	} else {
		codec, err := NewUDPServerCodec(method, key, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		inbound := &Inbound{udpCodec: codec, user: user, policyManager: p}
		h.manager = codec.sessions
		h.process = inbound.processUDP
	}
	codec, err := NewUDPPacketCodec(method, keys)
	if err != nil {
		t.Fatal(err)
	}
	h.client, err = codec.NewClientSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.manager.sessions.Range(func(_ uint64, s *ServerUDPSession) bool { s.Close(); return true }) })
	return h
}

func (h *lifecycleHarness) packet(t *testing.T) []byte {
	t.Helper()
	p, err := h.client.EncodePacket(net.UDPDestination(net.LocalHostIP, 53), []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release()
	return append([]byte(nil), p.Bytes()...)
}

func (h *lifecycleHarness) send(packet []byte, c *lifecycleConn) {
	h.sendContext(context.Background(), packet, c)
}

func (h *lifecycleHarness) sendContext(ctx context.Context, packet []byte, c *lifecycleConn) {
	c.packet = append([]byte(nil), packet...)
	_ = h.process(ctx, c, h.dispatch)
}
func newLifecycleConn() *lifecycleConn { return &lifecycleConn{replies: make(chan []byte, 16)} }
func lifecycleCases(t *testing.T, fn func(*testing.T, string, bool)) {
	for _, m := range []string{MethodAES128GCM, MethodAES256GCM, MethodChaCha20Poly1305} {
		t.Run(m+"/single", func(t *testing.T) { fn(t, m, false) })
		if m != MethodChaCha20Poly1305 {
			t.Run(m+"/multi", func(t *testing.T) { fn(t, m, true) })
		}
	}
}

func TestUDPAuthenticatedRebinding(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		first, delayed, moved, forged := h.packet(t), h.packet(t), h.packet(t), h.packet(t)
		oldConn, newConn := newLifecycleConn(), newLifecycleConn()
		h.send(first, oldConn)
		h.send(moved, newConn)
		h.send(delayed, oldConn)
		h.send(moved, oldConn) // replay must not move the path
		forged[len(forged)-1] ^= 1
		h.send(forged, oldConn) // unauthenticated high ID must not move it
		if got := h.dispatch.writer.count.Load(); got != 3 {
			t.Fatalf("forwarded %d packets, want 3", got)
		}
		if got := h.dispatch.count.Load(); got != 1 {
			t.Fatalf("created %d links, want 1", got)
		}
		s := h.manager.GetOrCreate(h.client.clientSessionID)
		if err := s.WriteToClient([]byte("reply")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-newConn.replies:
		default:
			t.Fatal("delayed packet reverted authenticated return path")
		}
		select {
		case <-oldConn.replies:
			t.Fatal("reply reached old path")
		default:
		}
	})
}

func TestUDPSessionEndsWithReturnPath(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		oldCtx, closeOld := context.WithCancel(context.Background())
		newCtx, closeNew := context.WithCancel(context.Background())
		defer closeNew()
		h.sendContext(oldCtx, h.packet(t), newLifecycleConn())
		h.sendContext(newCtx, h.packet(t), newLifecycleConn())
		sessCtx := h.dispatch.ctx
		closeOld()
		if sessCtx.Err() != nil {
			t.Fatal("first connection ended a session that moved away from it")
		}
		closeNew()
		select {
		case <-sessCtx.Done():
		case <-time.After(time.Second):
			t.Fatal("session outlived the connection carrying its replies")
		}
		if h.manager.GetOrCreate(h.client.clientSessionID).link.Load() != nil {
			t.Fatal("ended session is still stored")
		}
	})
}

func TestUDPSessionsKeepOwnInboundUser(t *testing.T) {
	inbound := &session.Inbound{Tag: "in"}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	m := NewUDPSessionManager(time.Hour)
	var dispatchers []*lifecycleDispatcher
	for n, email := range []string{"a@example.invalid", "b@example.invalid"} {
		s := m.GetOrCreate(uint64(n + 1))
		defer s.Close()
		s.User = &protocol.MemoryUser{Email: email}
		d := new(lifecycleDispatcher)
		if _, err := s.EnsureLink(ctx, newLifecycleConn(), net.UDPDestination(net.LocalHostIP, 53), d, lifecyclePolicy{idle: time.Hour}, nil); err != nil {
			t.Fatal(err)
		}
		dispatchers = append(dispatchers, d)
	}
	a := session.InboundFromContext(dispatchers[0].ctx).User
	b := session.InboundFromContext(dispatchers[1].ctx).User
	if a.Email != "a@example.invalid" || b.Email != "b@example.invalid" {
		t.Fatalf("sessions on one source address got users %s and %s", a.Email, b.Email)
	}
	if inbound.User != nil {
		t.Fatal("session user leaked into the shared inbound")
	}
}

func TestUDPConcurrentReplayAndInitialization(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		packet := h.packet(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 32 {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; h.send(packet, newLifecycleConn()) }()
		}
		close(start)
		wg.Wait()
		if got := h.dispatch.writer.count.Load(); got != 1 {
			t.Fatalf("accepted duplicate concurrently %d times", got)
		}
		if got := h.dispatch.count.Load(); got != 1 {
			t.Fatalf("initialized %d links", got)
		}
	})
}

func TestUDPAESDecryptRejectsReplay(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM} {
		t.Run(name, func(t *testing.T) {
			h := newLifecycleHarness(t, name, false)
			wire := h.packet(t)
			method := h.client.codec.method
			var header [16]byte
			h.client.codec.blockCipher.Decrypt(header[:], wire[:16])
			s := h.manager.GetOrCreate(binary.BigEndian.Uint64(header[:8]))
			id := binary.BigEndian.Uint64(header[8:])
			for n := 0; n < 2; n++ {
				_, err := s.DecryptAESPayload(method, h.client.codec.psk, s.SessionID, id, header[:], append([]byte(nil), wire[16:]...))
				if n == 0 && err != nil {
					t.Fatal(err)
				}
				if n == 1 && err != ErrPacketIdNotUnique {
					t.Fatalf("second decrypt got %v, want replay rejection", err)
				}
			}
		})
	}
}

func TestUDPCleanupKeepsReplacement(t *testing.T) {
	m := NewUDPSessionManager(time.Hour)
	old := m.GetOrCreate(123)
	m.Delete(old)
	replacement := m.GetOrCreate(123)
	m.Delete(old)
	if got := m.GetOrCreate(123); got != replacement {
		t.Fatal("late old-session cleanup deleted replacement")
	}
}

func TestUDPResponseKeepsAuthenticatedGeneration(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		conn := newLifecycleConn()
		h.send(h.packet(t), conn)
		old := h.manager.GetOrCreate(h.client.clientSessionID)
		defer old.Close()
		h.manager.Delete(old)
		old.LastActive.Store(1)
		replacement := h.manager.GetOrCreate(old.SessionID)
		b := buf.New()
		b.Write([]byte("response"))
		if err := h.dispatch.responses.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-conn.replies:
		case <-time.After(time.Second):
			t.Fatal("response did not arrive")
		}
		if old.LastActive.Load() < time.Now().Unix()-1 {
			t.Fatal("response did not refresh manager activity")
		}
		replacement.Lock()
		id := replacement.ServerSessionID
		replacement.Unlock()
		if id != 0 {
			t.Fatal("late response initialized replacement generation")
		}
	})
}

func TestUDPValidationDoesNotWaitForDispatchLock(t *testing.T) {
	h := newLifecycleHarness(t, MethodAES128GCM, false)
	wire := h.packet(t)
	s := h.manager.GetOrCreate(h.client.clientSessionID)
	var header [16]byte
	h.client.codec.blockCipher.Decrypt(header[:], wire[:16])
	s.Lock()
	defer s.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := s.DecryptAESPayload(h.client.codec.method, h.client.codec.psk, s.SessionID, binary.BigEndian.Uint64(header[8:]), header[:], wire[16:])
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("packet validation waits behind dispatch lock")
	}
}

func TestUDPReturnPathUpdateDoesNotAllocate(t *testing.T) {
	s := new(ServerUDPSession)
	conn := newLifecycleConn()
	var id uint64
	if allocs := testing.AllocsPerRun(1000, func() { id++; s.UpdateAuthenticatedConn(context.Background(), conn, id) }); allocs != 0 {
		t.Fatalf("return-path update allocated %g objects", allocs)
	}
}

type lifecycleBarrierAEAD struct {
	cipher.AEAD
	entered chan struct{}
	release chan struct{}
}

func (a *lifecycleBarrierAEAD) Open(dst, nonce, ciphertext, additional []byte) ([]byte, error) {
	a.entered <- struct{}{}
	<-a.release
	return a.AEAD.Open(dst, nonce, ciphertext, additional)
}

func TestUDPMultiUserCipherOwnerPublishedAtomically(t *testing.T) {
	for _, name := range []string{MethodAES128GCM, MethodAES256GCM} {
		t.Run(name, func(t *testing.T) {
			h := newLifecycleHarness(t, name, true)
			first, second := h.packet(t), h.packet(t)
			keyB := bytes.Repeat([]byte{3}, h.client.codec.method.KeySaltLength)
			userB := &protocol.MemoryUser{Email: "other@example.invalid", Account: &MemoryAccount{Key: keyB}}
			h.multi.usersByHash.Store(DeriveUserPSKHash(keyB), userB)
			var header [16]byte
			h.multi.udpMasterCipher.Decrypt(header[:], second[:16])
			hash := DeriveUserPSKHash(keyB)
			for n := range hash {
				hash[n] ^= header[n]
			}
			h.multi.udpMasterCipher.Encrypt(second[16:32], hash[:])
			s := h.manager.GetOrCreate(h.client.clientSessionID)
			barrier := &lifecycleBarrierAEAD{AEAD: h.client.clientBodyCipher, entered: make(chan struct{}, 2), release: make(chan struct{})}
			s.clientBodyCipher = barrier
			result := make(chan error, 2)
			go func() { _, _, err := h.multi.decodeUDPPacket(first); result <- err }()
			<-barrier.entered
			go func() { _, _, err := h.multi.decodeUDPPacket(second); result <- err }()
			select {
			case <-barrier.entered:
				close(barrier.release)
				t.Fatal("second receive entered before first user's identity was committed")
			case <-time.After(20 * time.Millisecond):
			}
			close(barrier.release)
			for range 2 {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			s.userMu.RLock()
			user, key := s.User, s.UserPSK
			s.userMu.RUnlock()
			if user == userB || !bytes.Equal(key, h.client.codec.psk) {
				t.Fatal("cipher owner and accounting user differ")
			}
		})
	}
}

type lifecycleGateDispatcher struct {
	routing.Dispatcher
	entered chan struct{}
	release chan struct{}
}

func (d *lifecycleGateDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	close(d.entered)
	<-d.release
	return d.Dispatcher.Dispatch(ctx, dest)
}

func TestUDPCloseDuringDispatchDoesNotResurrectSession(t *testing.T) {
	h := newLifecycleHarness(t, MethodAES128GCM, false)
	s := h.manager.GetOrCreate(h.client.clientSessionID)
	gate := &lifecycleGateDispatcher{Dispatcher: h.dispatch, entered: make(chan struct{}), release: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := s.EnsureLink(context.Background(), newLifecycleConn(), net.UDPDestination(net.LocalHostIP, 53), gate, lifecyclePolicy{idle: time.Hour}, nil)
		result <- err
	}()
	<-gate.entered
	s.Close()
	close(gate.release)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed session returned live link")
		}
	case <-time.After(time.Second):
		t.Fatal("link initialization did not finish")
	}
	b := buf.New()
	b.Write([]byte("late response"))
	if err := h.dispatch.responses.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
		t.Fatal("late-created response pipe was not interrupted")
	}
	if got := h.manager.GetOrCreate(s.SessionID); got == s {
		t.Fatal("closed session survived timer cleanup")
	}
}

func TestUDPReplyCarriesFullBuffer(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		conn := newLifecycleConn()
		h.send(h.packet(t), conn)
		b := buf.New()
		payload := b.Extend(buf.Size)
		for i := range payload {
			payload[i] = byte(i)
		}
		want := append([]byte(nil), payload...)
		if err := h.dispatch.responses.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
		select {
		case reply := <-conn.replies:
			decoded, err := h.client.DecodePacket(reply)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.Payload, want) {
				t.Fatalf("reply carried %d bytes, want the full %d", len(decoded.Payload), len(want))
			}
		case <-time.After(time.Second):
			t.Fatal("full-size reply was dropped")
		}
	})
}

func TestUDPUnauthenticatedPacketsStoreNoSession(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		for range 64 {
			junk := make([]byte, 64)
			rand.Read(junk)
			h.send(junk, newLifecycleConn())
		}
		forged := h.packet(t)
		forged[len(forged)-1] ^= 1
		h.send(forged, newLifecycleConn())
		count := func() (n int) {
			h.manager.sessions.Range(func(uint64, *ServerUDPSession) bool { n++; return true })
			return n
		}
		if n := count(); n != 0 {
			t.Fatalf("packets that failed authentication stored %d sessions", n)
		}
		h.send(h.packet(t), newLifecycleConn())
		if n := count(); n != 1 {
			t.Fatalf("an authenticated packet stored %d sessions, want 1", n)
		}
	})
}

func TestUDPStoreKeepsFirstSession(t *testing.T) {
	m := NewUDPSessionManager(time.Hour)
	// Each session stands for a first packet that called Load before any Store.
	newSession := func(key byte) *ServerUDPSession {
		return &ServerUDPSession{SessionID: 7, manager: m, UserPSK: []byte{key}}
	}
	if _, ok := m.Load(7); ok {
		t.Fatal("Load stored a session")
	}
	first := newSession(1)
	if got, ok := m.Store(first, 1); got != first || !ok {
		t.Fatal("first session was not stored")
	}
	if got, ok := m.Store(newSession(1), 2); got != first || !ok {
		t.Fatal("a new packet of the stored session was refused")
	}
	if _, ok := m.Store(newSession(1), 2); ok {
		t.Fatal("a replayed packet was accepted")
	}
	if _, ok := m.Store(newSession(2), 3); ok {
		t.Fatal("a packet decrypted with another key joined the session")
	}
}

func TestUDPReplayRejectedAfterSessionEnds(t *testing.T) {
	lifecycleCases(t, func(t *testing.T, method string, multi bool) {
		h := newLifecycleHarness(t, method, multi)
		first := h.packet(t)
		h.send(first, newLifecycleConn())
		h.manager.GetOrCreate(h.client.clientSessionID).end()
		h.send(first, newLifecycleConn())
		if got := h.dispatch.writer.count.Load(); got != 1 {
			t.Fatal("a packet of an ended session was accepted again")
		}
		h.send(h.packet(t), newLifecycleConn())
		if got := h.dispatch.writer.count.Load(); got != 2 {
			t.Fatal("the client could not go on after its session ended")
		}
	})
}
