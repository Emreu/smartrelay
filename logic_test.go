package main

import (
	"net"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	payload := []byte("hello amneziawg")
	pkt := encodeSessionID(42, payload)
	id, data, ok := decodeSessionID(pkt)
	if !ok || id != 42 || string(data) != string(payload) {
		t.Fatalf("round trip mismatch: id=%d ok=%v data=%q", id, ok, data)
	}
}

func TestDecodeSessionIDTooShort(t *testing.T) {
	if _, _, ok := decodeSessionID([]byte{0x01}); ok {
		t.Fatal("expected ok=false for 1-byte input")
	}
	if _, _, ok := decodeSessionID(nil); ok {
		t.Fatal("expected ok=false for nil input")
	}
}

func TestStripIPHeader(t *testing.T) {
	// Minimal 20-byte IPv4 header (IHL=5) followed by payload.
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // version 4, IHL 5
	payload := []byte("payload")
	buf := append(hdr, payload...)

	got := stripIPHeader(buf)
	if string(got) != string(payload) {
		t.Fatalf("stripIPHeader = %q, want %q", got, payload)
	}

	if stripIPHeader([]byte{0x45, 0x00}) != nil {
		t.Fatal("expected nil for buffer shorter than 20 bytes")
	}
}

func TestMirrorStateAssignsAndReusesSessionIDs(t *testing.T) {
	m := newMirrorState()
	a1 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	a2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222}

	s1 := m.sessionFor(a1)
	s1Again := m.sessionFor(a1)
	if s1.id != s1Again.id {
		t.Fatalf("expected same session ID for repeat client, got %d and %d", s1.id, s1Again.id)
	}

	s2 := m.sessionFor(a2)
	if s2.id == s1.id {
		t.Fatalf("expected distinct session IDs for distinct clients, both got %d", s1.id)
	}

	if _, ok := m.lookup(s1.id); !ok {
		t.Fatal("expected to find session by ID")
	}
}

func TestMirrorStateExpiry(t *testing.T) {
	m := newMirrorState()
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111}
	s := m.sessionFor(addr)
	s.lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())

	m.expire(time.Minute)

	if _, ok := m.lookup(s.id); ok {
		t.Fatal("expected session to be expired")
	}
}

func TestServerStateMaxSessions(t *testing.T) {
	// wgAddr points at a UDP server that doesn't need to exist: DialUDP
	// with a dialed (not connected-handshake) UDP socket never touches the
	// network since UDP dial is just local socket setup.
	wgAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 59999}
	st := newServerState(1)

	noop := func(id uint16, data []byte) {}

	s1, ok := st.getOrCreate(1, wgAddr, noop)
	if !ok || s1 == nil {
		t.Fatal("expected first session to be created")
	}
	defer s1.conn.Close()

	if _, ok := st.getOrCreate(1, wgAddr, noop); !ok {
		t.Fatal("expected re-fetching the same session ID to succeed")
	}

	if _, ok := st.getOrCreate(2, wgAddr, noop); ok {
		t.Fatal("expected second distinct session to be rejected at cap 1")
	}
}

func TestPeerLockLearnsAndEnforces(t *testing.T) {
	p := &peerLock{}
	a := net.ParseIP("1.2.3.4")
	b := net.ParseIP("5.6.7.8")

	if !p.allow(a) {
		t.Fatal("expected first-seen peer to be allowed")
	}
	if !p.allow(a) {
		t.Fatal("expected the locked peer to keep being allowed")
	}
	if p.allow(b) {
		t.Fatal("expected a different peer to be rejected once locked")
	}
}
