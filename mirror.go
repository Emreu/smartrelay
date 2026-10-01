package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type mirrorSession struct {
	id       uint16
	addr     *net.UDPAddr
	lastSeen atomic.Int64 // unix nano
}

// mirrorState maps between client UDP addresses and session IDs. The
// mirror side is the sole authority for session ID assignment.
type mirrorState struct {
	mu     sync.Mutex
	byAddr map[string]*mirrorSession
	byID   map[uint16]*mirrorSession
	nextID uint16
}

func newMirrorState() *mirrorState {
	return &mirrorState{
		byAddr: make(map[string]*mirrorSession),
		byID:   make(map[uint16]*mirrorSession),
		nextID: 1,
	}
}

func (m *mirrorState) sessionFor(addr *net.UDPAddr) *mirrorSession {
	key := addr.String()

	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.byAddr[key]; ok {
		s.lastSeen.Store(time.Now().UnixNano())
		return s
	}

	var id uint16
	for {
		id = m.nextID
		m.nextID++
		if _, taken := m.byID[id]; !taken {
			break
		}
	}
	s := &mirrorSession{id: id, addr: addr}
	s.lastSeen.Store(time.Now().UnixNano())
	m.byAddr[key] = s
	m.byID[id] = s
	log.Printf("mirror: new session %d for client %s", id, key)
	return s
}

func (m *mirrorState) lookup(id uint16) (*mirrorSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	return s, ok
}

func (m *mirrorState) expire(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout).UnixNano()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.byID {
		if s.lastSeen.Load() < cutoff {
			delete(m.byID, id)
			delete(m.byAddr, s.addr.String())
			log.Printf("mirror: expired session %d (%s)", id, s.addr)
		}
	}
}

func runMirror(proto int, peer net.IP, listenAddr *net.UDPAddr, timeout time.Duration) {
	udpConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		log.Fatalf("mirror: listen UDP: %v", err)
	}
	defer udpConn.Close()

	rawConn, err := net.ListenIP(fmt.Sprintf("ip4:%d", proto), &net.IPAddr{IP: net.IPv4zero})
	if err != nil {
		log.Fatalf("mirror: listen raw IP: %v (need root/CAP_NET_RAW)", err)
	}
	defer rawConn.Close()

	peerAddr := &net.IPAddr{IP: peer}
	state := newMirrorState()

	log.Printf("mirror: ready, clients -> %s, tunnel -> %s (proto %d)", listenAddr, peer, proto)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			state.expire(timeout)
		}
	}()

	// client -> tunnel
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("mirror: udp read error: %v", err)
				continue
			}
			s := state.sessionFor(addr)
			pkt := encodeSessionID(s.id, buf[:n])
			if _, err := rawConn.WriteTo(pkt, peerAddr); err != nil {
				log.Printf("mirror: raw write error: %v", err)
				continue
			}
			debugf("mirror: client %s -> session %d, %d bytes", addr, s.id, n)
		}
	}()

	// tunnel -> client
	buf := make([]byte, 65535)
	for {
		n, addr, err := rawConn.ReadFrom(buf)
		if err != nil {
			log.Printf("mirror: raw read error: %v", err)
			continue
		}
		ipAddr, ok := addr.(*net.IPAddr)
		if !ok || !ipAddr.IP.Equal(peer) {
			debugf("mirror: dropping raw packet from unexpected source %s", addr)
			continue
		}
		payload := stripIPHeader(buf[:n])
		id, data, ok := decodeSessionID(payload)
		if !ok {
			continue
		}
		s, ok := state.lookup(id)
		if !ok {
			debugf("mirror: dropping packet for unknown session %d", id)
			continue
		}
		if _, err := udpConn.WriteToUDP(data, s.addr); err != nil {
			log.Printf("mirror: udp write error: %v", err)
			continue
		}
		s.lastSeen.Store(time.Now().UnixNano())
		debugf("mirror: session %d -> client %s, %d bytes", id, s.addr, len(data))
	}
}
