package main

import (
	"bytes"
	"strings"

	"github.com/algorand/go-algorand-sdk/types"
)

// prefixMatcher decides whether an Algorand address begins with the target
// prefix. The address string is base32(pubkey || checksum) using StdEncoding
// with no padding, where checksum = last 4 bytes of sha512_256(pubkey).
//
// The leading base32 chars encode the leading bits of the byte stream
// (MSB-first), so the first L chars depend only on the first ceil(5L/8) bytes.
// For L <= 51 those bits lie entirely within the 32-byte public key, so the
// checksum + base32 + string work can be skipped: we compare the raw public key
// bytes against the prefix decoded once into bytes plus a top-bit mask. For L
// > 51 (or a non-base32 prefix) we fall back to the exact string compare.
//
// The decision is identical to strings.HasPrefix(addressString, prefix) for
// every case, so a search produces exactly the same matches as before.
type prefixMatcher struct {
	prefix string // the raw prefix, kept for the slow path

	fast     bool // use the raw-public-key fast path
	want     []byte // full bytes that must match pubkey[0:len(want)] exactly
	leftover int    // number of significant bits (1..7) in the partial final byte, 0 if none
	partial  byte   // expected value of those top `leftover` bits, shifted into place
}

// newPrefixMatcher compiles the prefix once. It returns a matcher whose
// matchPublicKey gives the same result as strings.HasPrefix on the address
// string, but without building that string on the fast path.
func newPrefixMatcher(prefix string) prefixMatcher {
	m := prefixMatcher{prefix: prefix}
	// 5*L <= 256  <=>  L <= 51: the whole prefix is fixed by the 32-byte pubkey.
	if len(prefix) > 0 && 5*len(prefix) <= 256 {
		if want, partial, leftover, ok := decodePrefixBits(prefix); ok {
			m.fast = true
			m.want = want
			m.leftover = leftover
			m.partial = partial
		}
	}
	return m
}

// matchPublicKey reports whether the address whose public key is pk (32 bytes)
// starts with the configured prefix.
func (m prefixMatcher) matchPublicKey(pk []byte) bool {
	if !m.fast {
		var a types.Address
		copy(a[:], pk)
		return strings.HasPrefix(a.String(), m.prefix)
	}
	if len(m.want) > 0 {
		if len(pk) < len(m.want) || !bytes.Equal(pk[:len(m.want)], m.want) {
			return false
		}
	}
	if m.leftover > 0 {
		// The partial byte's significant bits are its top `leftover` bits.
		if len(pk) <= len(m.want) || (pk[len(m.want)]&maskTop(m.leftover)) != m.partial {
			return false
		}
	}
	return true
}

// maskTop returns the byte whose top n bits are set (n in 1..7).
func maskTop(n int) byte { return 0xFF << (8 - n) }

// decodePrefixBits turns a base32 prefix into the raw bytes + partial-byte mask
// that a public key must match. ok is false if any character is outside the
// base32 StdEncoding alphabet (A-Z, 2-7), in which case the caller falls back
// to the string compare.
func decodePrefixBits(prefix string) (want []byte, partial byte, leftover int, ok bool) {
	var acc uint64
	bits := 0
	for i := 0; i < len(prefix); i++ {
		v, valid := base32Value(prefix[i])
		if !valid {
			return nil, 0, 0, false
		}
		acc = (acc << 5) | uint64(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			want = append(want, byte(acc>>bits))
			acc &= (1 << bits) - 1 // keep only the still-unemitted low bits
		}
	}
	if bits > 0 {
		partial = byte(acc) << (8 - bits)
	}
	return want, partial, bits, true
}

// base32Value maps a base32 StdEncoding character to its 5-bit value.
func base32Value(c byte) (int, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), true
	case c >= '2' && c <= '7':
		return int(c - '2') + 26, true
	default:
		return 0, false
	}
}
