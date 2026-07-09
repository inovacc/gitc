// Package uuidv7 generates RFC 9562 version-7 UUIDs: a 48-bit millisecond
// timestamp prefix followed by random bits. Because the timestamp leads, the
// values are time-ordered and lexicographically sortable — gitc uses that to
// name each managed-git install directory so they sort chronologically and the
// oldest can be garbage-collected. Pure stdlib (crypto/rand + time), no deps.
package uuidv7

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// New returns a new UUIDv7 as its canonical 36-char hyphenated string.
func New() (string, error) {
	var b [16]byte

	ms := uint64(time.Now().UnixMilli()) //nolint:gosec // milliseconds fit in 48 bits until year 10889

	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("uuidv7: read random: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x70 // version 7 in the high nibble
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant (10xxxxxx)

	return format(b), nil
}

// format renders the 16 bytes as 8-4-4-4-12 lowercase hex.
func format(b [16]byte) string {
	var buf [36]byte

	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])

	return string(buf[:])
}
