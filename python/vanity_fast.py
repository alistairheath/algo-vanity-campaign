"""Faster Algorand vanity search, using the same idea as the Go version.

The original loop calls algosdk's account.generate_account() for every attempt,
which builds the full address string (SHA-512/256 checksum, base32, string
allocation) just to run str.startswith(). An address is base32(public_key ||
checksum), and base32 is read most-significant-bit first, so the first L
characters depend only on the first ceil(5L/8) bytes of the 32-byte public key
(for L <= 51). So we can decode the prefix into bytes and bit masks once and
compare the raw public key. The address string is only built for a real match.

Every candidate is still a real ed25519 account from a secure random seed
(os.urandom), and the result is identical to str.startswith on the address.
"""
import base64
import os

from algosdk import encoding
from nacl.bindings import crypto_sign_seed_keypair

_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_VALUE = {c: i for i, c in enumerate(_B32)}
SEED_SIZE = 32
BATCH = 1024  # seeds read from the OS per os.urandom call


class PrefixMatcher:
    """Matches an address prefix against a raw 32-byte public key."""

    def __init__(self, prefix):
        self.prefix = prefix
        self.fast = bool(prefix) and 5 * len(prefix) <= 256 and all(c in _B32_VALUE for c in prefix)
        if not self.fast:
            return
        acc = 0
        bits = 0
        want = bytearray()
        for c in prefix:
            acc = (acc << 5) | _B32_VALUE[c]
            bits += 5
            while bits >= 8:
                bits -= 8
                want.append((acc >> bits) & 0xFF)
                acc &= (1 << bits) - 1
        self.want = bytes(want)
        self.leftover = bits
        self.mask = (0xFF << (8 - bits)) & 0xFF if bits else 0
        self.partial = (acc << (8 - bits)) & 0xFF if bits else 0

    def match(self, public_key):
        if not self.fast:
            return encoding.encode_address(public_key).startswith(self.prefix)
        n = len(self.want)
        if n and public_key[:n] != self.want:
            return False
        if self.leftover and (public_key[n] & self.mask) != self.partial:
            return False
        return True


def search(prefix, attempts):
    """Make exactly `attempts` tries. Returns a list of (address, private_key) matches.

    private_key is the same base64 of seed+public key that algosdk returns.
    """
    matcher = PrefixMatcher(prefix)
    matches = []
    done = 0
    while done < attempts:
        n = min(BATCH, attempts - done)
        seeds = os.urandom(n * SEED_SIZE)
        for i in range(n):
            seed = seeds[i * SEED_SIZE:(i + 1) * SEED_SIZE]
            public_key, _ = crypto_sign_seed_keypair(seed)
            if matcher.match(public_key):
                address = encoding.encode_address(public_key)
                matches.append((address, base64.b64encode(seed + public_key).decode()))
        done += n
    return matches
