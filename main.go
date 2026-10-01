// wgrelay tunnels AmneziaWG UDP traffic across a path that blocks TCP/UDP
// but passes an arbitrary IP protocol number, by relaying over raw IP.
//
// Two modes, same binary:
//
//	mirror  — runs on the domestic box. Accepts AmneziaWG clients over normal
//	          UDP, forwards each client's traffic over the raw-IP tunnel to
//	          the server, keyed by a per-client session ID.
//	server  — runs on the VPS next to the real AmneziaWG server. Unwraps raw
//	          IP packets from the mirror and relays each session to the
//	          local AmneziaWG server over loopback UDP.
package main

import (
	"flag"
	"log"
	"net"
	"time"
)

func main() {
	mode := flag.String("mode", "", "relay mode: server or mirror")
	proto := flag.Int("proto", 253, "IP protocol number for the raw tunnel (0-255)")
	peer := flag.String("peer", "", "peer IP address (required for mirror; optional for server, learned from the first packet if omitted)")
	listen := flag.String("listen", "", "UDP address to accept AmneziaWG clients on (mirror mode), e.g. 0.0.0.0:51820")
	wgAddr := flag.String("wg-addr", "", "local AmneziaWG server UDP address (server mode), e.g. 127.0.0.1:51821")
	sessionTimeout := flag.Duration("session-timeout", 300*time.Second, "idle session timeout")
	maxSessions := flag.Int("max-sessions", 256, "maximum concurrent sessions (server mode)")
	flag.BoolVar(&verbose, "v", false, "verbose logging")
	flag.Parse()

	if *proto < 0 || *proto > 255 {
		log.Fatalf("-proto must be between 0 and 255")
	}

	switch *mode {
	case "mirror":
		if *peer == "" || *listen == "" {
			log.Fatalf("mirror mode requires -peer and -listen")
		}
		peerIP := net.ParseIP(*peer).To4()
		if peerIP == nil {
			log.Fatalf("invalid -peer address %q", *peer)
		}
		listenAddr, err := net.ResolveUDPAddr("udp4", *listen)
		if err != nil {
			log.Fatalf("invalid -listen address: %v", err)
		}
		runMirror(*proto, peerIP, listenAddr, *sessionTimeout)

	case "server":
		if *wgAddr == "" {
			log.Fatalf("server mode requires -wg-addr")
		}
		wgUDPAddr, err := net.ResolveUDPAddr("udp4", *wgAddr)
		if err != nil {
			log.Fatalf("invalid -wg-addr: %v", err)
		}
		var peerIP net.IP
		if *peer != "" {
			peerIP = net.ParseIP(*peer).To4()
			if peerIP == nil {
				log.Fatalf("invalid -peer address %q", *peer)
			}
		}
		runServer(*proto, peerIP, wgUDPAddr, *sessionTimeout, *maxSessions)

	default:
		log.Fatalf("specify -mode server|mirror")
	}
}
