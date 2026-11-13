package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/algorand/go-algorand-sdk/crypto"
)

// searchBatch is the ONE shared search used by both the -count benchmark path
// (runBench) and the interactive -prefix path (main.go). It spawns the workers
// itself and makes exactly attempts tries (attempts == 0 means run until ctx is
// cancelled), calling onMatch for every account whose address starts with the
// prefix.
//
// Each try is a real ed25519 account from a cryptographically secure random 32-
// byte seed (ed25519.NewKeyFromSeed, the same derivation crypto.GenerateAccount
// uses). The per-attempt prefix test runs on the raw 32-byte public key with the
// byte-level prefixMatcher (prefix.go) instead of building the address string
// (SHA-512_256 checksum + base32 + string allocation) just to run a prefix
// check; the address string is only built for real matches. Seeds are read in
// batches with a single crypto/rand.Read per batch and served from memory,
// removing the per-attempt rand.Read call and the per-attempt allocation.
//
// Workers share a per-chunk work cursor: each grabs the next contiguous chunk
// of `chunk` attempts with one atomic add, so the atomic is touched once per
// chunk (not per attempt) and the hot loop stays contention-free. progress
// (may be nil) is added once per chunk with the attempts just completed: nil
// for the benchmark (which times the whole run), and the interactive printer's
// global counter so its live rate keeps working.
func searchBatch(ctx context.Context, prefix string, attempts uint64, workers int, progress *uint64, onMatch func(crypto.Account)) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	matcher := newPrefixMatcher(prefix)

	// Reset the shared work cursor so repeated calls are independent.
	atomic.StoreUint64(&workNext, 0)

	// Largest batch of seeds one crypto/rand.Read serves per worker per round.
	// 1024 seeds = 32 KiB, comfortably under getrandom's 256-byte-guaranteed
	// read size, so each rand.Read is a single non-short kernel read.
	const chunk = 1024

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var seeds [chunk * ed25519.SeedSize]byte
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				start := atomic.AddUint64(&workNext, chunk) - chunk
				if attempts > 0 && start >= attempts {
					return
				}
				end := start + chunk
				if attempts > 0 && end > attempts {
					end = attempts
				}
				if _, err := rand.Read(seeds[:]); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(4)
				}
				for i := start; i < end; i++ {
					seed := seeds[(i-start)*ed25519.SeedSize : (i-start+1)*ed25519.SeedSize]
					priv := ed25519.NewKeyFromSeed(seed)
					pub := priv[ed25519.SeedSize:] // the 32-byte public key
					// Byte-level prefix test on the raw public key: no checksum,
					// no base32, no string allocation unless it actually matches.
					if matcher.matchPublicKey(pub) {
						var a crypto.Account
						a.PublicKey = ed25519.PublicKey(pub)
						a.PrivateKey = priv
						copy(a.Address[:], pub)
						onMatch(a)
					}
				}
				if progress != nil {
					atomic.AddUint64(progress, uint64(end-start))
				}
			}
		}()
	}
	wg.Wait()
}

// workNext is the shared per-worker work cursor for searchBatch. Each worker
// takes a contiguous chunk of [0, attempts) at a time.
var workNext uint64

// writeMatches is the shared output writer for a search that collects matches:
// it writes every matched account as {"address","private_key"} lines to
// <outDir>/matches.jsonl and a summary to <outDir>/result.json.
func writeMatches(outDir string, attempts uint64, prefix string, matches []string) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	if err := os.WriteFile(filepath.Join(outDir, "matches.jsonl"), []byte(strings.Join(matches, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	res, _ := json.Marshal(map[string]any{"attempts": attempts, "prefix": prefix, "matches": len(matches)})
	if err := os.WriteFile(filepath.Join(outDir, "result.json"), res, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
