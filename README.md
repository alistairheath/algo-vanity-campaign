# Algorand Vanity Address Generator

A fast, multi-core command-line tool that searches for an Algorand account whose address starts with a prefix you choose, for example `DIIISCO`.

Every candidate is a real ed25519 account made from a cryptographically secure random seed. When a match is found the tool prints the address, the 25-word mnemonic and the private key.

## Requirements

- [Go](https://go.dev/dl/) 1.25 or newer
- Nothing else: dependencies are vendored, so the build works offline

## Build

```sh
go build -o vanity .
```

You can also skip the build and use `go run . [-prefix=...]` in place of `./vanity [-prefix=...]` below.

## Usage

```sh
./vanity                 # searches for the default prefix, ALGO
./vanity -prefix=HELLO   # searches for a prefix you choose
```

Example output:

```
Searching for prefix="ALGO" using 14 workers (batch=1000, interval=1.00s)
[1.0s] Attempts:       861184 (Δ  861184)  Rate:  861184.00/s

---- FOUND! ----
Address: ALGO...
Mnemonic: word1 word2 ... word25
PrivateKey (hex): ...
Total attempts: 1234567
Elapsed: 1.43s, Avg rate: 863000.00/s
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-prefix` | `ALGO` | Address prefix to look for. Case-sensitive. |
| `-workers` | number of CPUs | Number of worker goroutines. |
| `-interval` | `1.0` | Seconds between status lines. |
| `-batch` | `1000` | Kept for compatibility. It has no effect. |
| `-count` | `0` | Benchmark mode: stop after exactly this many attempts. Needs `-out`. |
| `-out` | | Benchmark mode: directory for `matches.jsonl` and `result.json`. |

### Choosing a prefix

- Algorand addresses use the base32 alphabet: capital letters `A-Z` and digits `2-7`. A prefix with any other character (such as `0`, `1`, `8`, `9` or a lowercase letter) can never match.
- Each extra character makes the search 32 times longer on average. At roughly 800,000 attempts per second on a modern laptop:

| Prefix length | Average attempts | Average time |
|---|---|---|
| 4 | about 1 million | about 1 second |
| 5 | about 34 million | about 40 seconds |
| 6 | about 1 billion | about 20 minutes |
| 7 | about 34 billion | about 12 hours |
| 8 | about 1.1 trillion | about 16 days |

These are averages. You can get lucky or unlucky, and the tool runs until it finds a match, so press `Ctrl+C` to stop.

## Benchmark mode

`-count` runs a fixed number of attempts and writes the result to a folder, which is how the speed was measured:

```sh
./vanity -prefix=K -count=2000000 -out ./out
```

This writes `out/matches.jsonl` (one `{"address","private_key"}` per match) and `out/result.json` (`{"attempts","prefix","matches"}`).

## Security

- The mnemonic and private key give full control of the account. Anyone who sees them can spend the funds.
- Run the tool on a machine you trust, keep the output private, and store the mnemonic offline.
- Terminal history and screen recordings can keep a copy of what was printed.

## How it works

- `search.go` is the single search loop used by both normal mode and `-count`. It reads random seeds in batches and derives a key for each.
- `prefix.go` turns the prefix into raw bytes and bit masks once, then checks each candidate's 32-byte public key directly. It skips building the full address (checksum and base32) for every attempt. Prefixes longer than 51 characters use the plain string comparison.
- Tests: `go test ./...` (about 45 seconds).
