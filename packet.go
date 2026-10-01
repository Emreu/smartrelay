package main

import (
	"encoding/binary"
	"log"
)

const sessionHeaderLen = 2

// encodeSessionID prepends a 2-byte big-endian session ID to payload.
func encodeSessionID(id uint16, payload []byte) []byte {
	buf := make([]byte, sessionHeaderLen+len(payload))
	binary.BigEndian.PutUint16(buf, id)
	copy(buf[sessionHeaderLen:], payload)
	return buf
}

func decodeSessionID(buf []byte) (id uint16, payload []byte, ok bool) {
	if len(buf) < sessionHeaderLen {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(buf), buf[sessionHeaderLen:], true
}

// stripIPHeader removes the IPv4 header that the kernel includes on reads
// from a raw IPv4 socket (it is never included on writes).
func stripIPHeader(buf []byte) []byte {
	if len(buf) < 20 {
		return nil
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < 20 || ihl > len(buf) {
		return nil
	}
	return buf[ihl:]
}

var verbose bool

func debugf(format string, args ...any) {
	if verbose {
		log.Printf(format, args...)
	}
}
