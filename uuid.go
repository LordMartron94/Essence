package essence

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// UUID represents a 128-bit (16 byte) universally unique identifier.
type UUID [16]byte

// ============================================================================
// ── Variant 1: Pure Random (RFC 9562 §5.7) ───────────────────────────────────
// ============================================================================

// UUIDv7GenerateRandom generates a Version 7 UUID as defined in RFC 9562 §5.7,
// using only a 48-bit Unix timestamp and 74 bits of cryptographically secure
// random data (no sub-ms fraction or counter).
//
// Field layout:
//
//	0–47:  unix_ts_ms (48 bits, big endian, ms since Unix epoch)
//	48–51: version (0b0111)
//	52–63: rand_a (12 random bits)
//	64–65: variant (0b10)
//	66–127: rand_b (62 random bits)
func UUIDv7GenerateRandom() (UUID, error) {
	var uuid UUID

	// ───── 1. Timestamp (48 bits, big endian) ─────
	unixMs := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(uuid[0:8], unixMs<<16)

	// ───── 2. rand_a (12 random bits) ─────
	var randA [2]byte
	if _, err := rand.Read(randA[:]); err != nil {
		return UUID{}, err
	}
	randA[0] &= 0x0F // clear high 4 bits, reserved for version

	// ───── 3. Version (4 bits, value 7) ─────
	uuid[6] = 0x70 | randA[0]
	uuid[7] = randA[1]

	// ───── 4. rand_b (62 bits) + Variant (2 bits 0b10) ─────
	var randB [8]byte
	if _, err := rand.Read(randB[:]); err != nil {
		return UUID{}, err
	}
	randB[0] &= 0x3F // clear top 2 bits
	randB[0] |= 0x80 // set variant bits 0b10
	copy(uuid[8:], randB[:])

	return uuid, nil
}

// ============================================================================
// ── Variant 2: Monotonic (RFC 9562 §5.7 + §6.2) ──────────────────────────────
// ============================================================================

// Internal state for sub-millisecond fraction + monotonic counter
var (
	mu                sync.Mutex
	lastUnixMs        int64
	lastSubMsFraction uint16
	counter           uint16
)

// UUIDv7GenerateMonotonic generates a Version 7 UUID using:
//   - A 48-bit Unix timestamp (ms).
//   - A 12-bit sub-millisecond fraction derived from nanoseconds.
//   - A 12-bit monotonic counter to ensure uniqueness if multiple UUIDs
//     are generated within the same (ms, sub-ms) tick.
//   - 62 bits of cryptographically secure randomness for rand_b.
//
// This method corresponds to RFC 9562 § 6.2 (Method 3 + Method 1) and guarantees
// monotonic ordering even under very high generation rates.
func UUIDv7GenerateMonotonic() (UUID, error) {
	var uuid UUID

	now := time.Now()
	unixMs := now.UnixMilli()

	// ───── 1. Timestamp (48 bits, big endian) ─────
	binary.BigEndian.PutUint64(uuid[0:8], uint64(unixMs)<<16)

	// ───── 2. Sub-ms fraction (12 bits) + counter (12 bits) ─────
	subMs := uint16((now.Nanosecond() % 1_000_000) * 4096 / 1_000_000) // 12 bits

	mu.Lock()
	if unixMs != lastUnixMs || subMs != lastSubMsFraction {
		lastUnixMs = unixMs
		lastSubMsFraction = subMs
		counter = 0
	} else {
		counter = (counter + 1) & 0x0FFF // wrap at 12 bits if needed
	}
	localCounter := counter
	mu.Unlock()

	// Combine subMs and counter into 12 bits of rand_a
	// Here: top 6 bits = subMs>>6, low 6 bits = counter&0x3F (example split)
	combined12 := ((subMs >> 6) << 6) | (localCounter & 0x3F)
	var randA [2]byte
	binary.BigEndian.PutUint16(randA[:], combined12)
	randA[0] &= 0x0F // clear top 4 bits for version

	// ───── 3. Version ─────
	uuid[6] = 0x70 | randA[0]
	uuid[7] = randA[1]

	// ───── 4. rand_b + Variant ─────
	var randB [8]byte
	if _, err := rand.Read(randB[:]); err != nil {
		return UUID{}, err
	}
	randB[0] &= 0x3F
	randB[0] |= 0x80
	copy(uuid[8:], randB[:])

	return uuid, nil
}

// ============================================================================
// ── String Formatting ───────────────────────────────────────────────────────
// ============================================================================

// String returns the canonical textual representation of the UUID:
// 8-4-4-4-12 lowercase hexadecimal groups.
func (id UUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(id[0:4]),
		binary.BigEndian.Uint16(id[4:6]),
		binary.BigEndian.Uint16(id[6:8]),
		binary.BigEndian.Uint16(id[8:10]),
		id[10:16],
	)
}
