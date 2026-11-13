#!/usr/bin/env python3
"""Benchmark the original Python search against the improved one.

Both run in a single process for the same number of seconds on the same prefix
and report attempts per second. A correctness check compares the matcher with
str.startswith on the real address for many random keys first.

Usage:
    python benchmark.py [--prefix ZZZZZZ] [--seconds 10] [--rounds 3]
"""
import argparse
import os
import statistics
import time

from algosdk import account, encoding
from nacl.bindings import crypto_sign_seed_keypair

import vanity_fast


def original(prefix, seconds):
    """The method generate.py uses: build the whole address for every attempt."""
    attempts = 0
    deadline = time.perf_counter() + seconds
    start = time.perf_counter()
    while time.perf_counter() < deadline:
        for _ in range(500):
            _, address = account.generate_account()
            address.startswith(prefix)
        attempts += 500
    return attempts / (time.perf_counter() - start)


def improved(prefix, seconds):
    """vanity_fast.search: byte-level prefix test on the raw public key."""
    attempts = 0
    deadline = time.perf_counter() + seconds
    start = time.perf_counter()
    while time.perf_counter() < deadline:
        vanity_fast.search(prefix, 2048)
        attempts += 2048
    return attempts / (time.perf_counter() - start)


def check_correctness(samples=20000):
    """The fast matcher must agree with str.startswith for every prefix and key."""
    prefixes = ["A", "K7", "2XM", "ALGO", "ZZ", "7", "ABCDE", "QQQQQQQQ"]
    for prefix in prefixes:
        matcher = vanity_fast.PrefixMatcher(prefix)
        hits = 0
        for _ in range(samples):
            public_key, _ = crypto_sign_seed_keypair(os.urandom(32))
            expected = encoding.encode_address(public_key).startswith(prefix)
            assert matcher.match(public_key) == expected, (prefix, public_key.hex())
            hits += expected
    # Keys built to hit the prefix exactly, including non-byte-aligned lengths.
    for prefix in ["A", "K7", "2XM", "ALGO", "ABCDE", "HELLO", "Z" * 7]:
        matcher = vanity_fast.PrefixMatcher(prefix)
        padded = prefix + "A" * (52 - len(prefix))
        import base64
        raw = base64.b32decode(padded + "====")
        assert matcher.match(raw[:32]), prefix
        assert encoding.encode_address(raw[:32]).startswith(prefix), prefix
    print("correctness check passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", default="ZZZZZZ", help="prefix to search for (default: unlikely to match)")
    parser.add_argument("--seconds", type=float, default=10.0, help="seconds per round")
    parser.add_argument("--rounds", type=int, default=3, help="rounds per method (runs are interleaved)")
    args = parser.parse_args()

    check_correctness()
    print(f"prefix={args.prefix!r}, {args.seconds:.0f}s x {args.rounds} rounds per method, single process\n")

    old, new = [], []
    for r in range(1, args.rounds + 1):
        old.append(original(args.prefix, args.seconds))
        new.append(improved(args.prefix, args.seconds))
        print(f"round {r}: original {old[-1]:>10,.0f}/s   improved {new[-1]:>10,.0f}/s")

    o, n = statistics.median(old), statistics.median(new)
    print(f"\nmedian: original {o:,.0f}/s   improved {n:,.0f}/s   speedup {n / o:.2f}x")


if __name__ == "__main__":
    main()
