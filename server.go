package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type serverSession struct {
	id       uint16
	conn     *net.UDPConn
	lastSeen atomic.Int64 // unix nano
}

// serverState maps session IDs (assigned by the mirror) to a dedicated
// loopback UDP socket connected to the local AmneziaWG server. The dedicated
// socket is what lets replies from a single shared WireGuard server be
// routed back to the right session without any port concept on the raw hop.
type serverState struct {
	mu          sync.Mutex
	sessions    map[uint16]*serverSession
	maxSessions int
}

func newServerState(max int) *serverState {
	return &serverState{sessions: make(map[uint16]*serverSession), maxSessions: max}
}

// getOrCreate returns the session for id, dialing a new loopback socket to
// wgAddr and starting its reply-reader goroutine if this is the first time
// id has been seen. onReply is invoked (from the reader goroutine) for every
// datagram the local AmneziaWG server sends back for this session.
func (s *serverState) getOrCreate(id uint16, wgAddr *net.UDPAddr, onReply func(id uint16, data []byte)) (*serverSession, bool) {
	s.mu.Lock()
	if sess, ok := s.sessions[id]; ok {
		s.mu.Unlock()
		return sess, true
	}
	if len(s.sessions) >= s.maxSessions {
		s.mu.Unlock()
		return nil, false
	}
	s.mu.Unlock()

	conn, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		log.Printf("server: dial wg-addr failed for session %d: %v", id, err)
		return nil, false
	}

	s.mu.Lock()
	if existing, ok := s.sessions[id]; ok {
		// Lost a race with another goroutine creating the same session.
		s.mu.Unlock()
		conn.Close()
		return existing, true
	}
	sess := &serverSession{id: id, conn: conn}
	sess.lastSeen.Store(time.Now().UnixNano())
	s.sessions[id] = sess
	s.mu.Unlock()

	log.Printf("server: new session %d -> %s", id, wgAddr)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return // socket closed on expiry
				}
				// e.g. ECONNREFUSED from an ICMP port-unreachable; transient.
				debugf("server: session %d wg read error: %v", id, err)
				continue
			}
			sess.lastSeen.Store(time.Now().UnixNano())
			onReply(id, append([]byte(nil), buf[:n]...))
		}
	}()

	return sess, true
}

func (s *serverState) touch(id uint16) {
	s.mu.Lock()
	sess, ok := s.sessions[id]
	s.mu.Unlock()
	if ok {
		sess.lastSeen.Store(time.Now().UnixNano())
	}
}

func (s *serverState) expire(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout).UnixNano()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.lastSeen.Load() < cutoff {
			sess.conn.Close()
			delete(s.sessions, id)
			log.Printf("server: expired session %d", id)
		}
	}
}

// peerLock pins the raw-tunnel peer to a single IP: either given up front
// via -peer, or learned from the first packet received and locked from then
// on ("trust on first use", appropriate for a fixed point-to-point link).
type peerLock struct {
	mu sync.Mutex
	ip net.IP
}

func (p *peerLock) allow(src net.IP) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ip == nil {
		p.ip = src
		log.Printf("server: locked peer to %s", src)
		return true
	}
	return p.ip.Equal(src)
}

func (p *peerLock) get() net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ip
}

func runServer(proto int, peer net.IP, wgAddr *net.UDPAddr, timeout time.Duration, maxSessions int) {
	rawConn, err := net.ListenIP(fmt.Sprintf("ip4:%d", proto), &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		log.Fatalf("server: listen raw IP: %v (need root/CAP_NET_RAW)", err)
	}
	defer rawConn.Close()

	lock := &peerLock{}
	if peer != nil {
		lock.ip = peer
	}

	state := newServerState(maxSessions)

	onReply := func(id uint16, data []byte) {
		dst := lock.get()
		if dst == nil {
			return
		}
		pkt := encodeSessionID(id, data)
		if _, err := rawConn.WriteTo(pkt, &net.IPAddr{IP: dst}); err != nil {
			log.Printf("server: raw write error: %v", err)
			return
		}
		debugf("server: session %d -> mirror, %d bytes", id, len(data))
	}

	log.Printf("server: ready, tunnel proto %d -> wg %s", proto, wgAddr)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			state.expire(timeout)
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, addr, err := rawConn.ReadFrom(buf)
		if err != nil {
			log.Printf("server: raw read error: %v", err)
			continue
		}
		ipAddr, ok := addr.(*net.IPAddr)
		if !ok || !lock.allow(ipAddr.IP) {
			debugf("server: dropping raw packet from unexpected source %s", addr)
			continue
		} else {
			debugf("server: received raw packet from %s length=%d %+v = %s", addr, n, buf[:n], buf[:n])
		}

		payload := buf[:n]
		id, data, ok := decodeSessionID(payload)
		if !ok {
			continue
		}
		sess, ok := state.getOrCreate(id, wgAddr, onReply)
		if !ok {
			debugf("server: dropping packet for session %d (at capacity or dial failed)", id)
			continue
		}
		if _, err := sess.conn.Write(data); err != nil {
			log.Printf("server: wg write error: %v", err)
			continue
		}
		state.touch(id)
		debugf("server: mirror -> session %d, %d bytes", id, len(data))
	}
}
