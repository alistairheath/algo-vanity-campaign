package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/algorand/go-algorand-sdk/crypto"
)

// runBench makes exactly count attempts across the workers and writes every
// address that starts with prefix to <out>/matches.jsonl, as
// {"address", "private_key"} lines (private_key is the 64-byte ed25519 key in
// hex). The benchmark kit times this run from outside and checks every match,
// so the attempts must be real Algorand accounts made from secure random seeds.
//
// The search itself is the shared searchBatch (search.go), which is also what
// the interactive -prefix path (main.go) uses: the same byte-level
// prefixMatcher (prefix.go) and batched entropy, and the same real ed25519
// accounts. Optimizations preserved:
//   - Per-attempt prefix test runs on the raw 32-byte public key with a
//     byte-level compare instead of building the address string (SHA-512_256
//     checksum + base32 encode + string allocation) just to run a prefix check.
//     The address string is only built for real matches.
//   - Seeds are read in batches with a single crypto/rand.Read and derived with
//     ed25519.NewKeyFromSeed, keeping only the 32-byte public key for the search
//     and materializing the full 64-byte private key + address only on a match.
//   - Workers share a per-chunk work cursor (one atomic add per chunk of
//     `chunk` attempts), so the atomic is touched once per chunk, not per
//     attempt, and the hot loop stays contention-free.
func runBench(prefix string, workers int, count uint64, outDir string) {
	if outDir == "" {
		fmt.Fprintln(os.Stderr, "-out is required with -count")
		os.Exit(2)
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(workers)

	var (
		mu      sync.Mutex
		matches []string
	)
	// progress is nil: the benchmark times the whole run and knows the attempt
	// count is exactly count, so it needs no running counter.
	searchBatch(context.Background(), prefix, count, workers, nil, func(a crypto.Account) {
		b, _ := json.Marshal(map[string]string{
			"address":     a.Address.String(),
			"private_key": hex.EncodeToString(a.PrivateKey),
		})
		mu.Lock()
		matches = append(matches, string(b))
		mu.Unlock()
	})

	writeMatches(outDir, count, prefix, matches)
}
