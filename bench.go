package main

import (
	"encoding/hex"
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

// runBench makes exactly count attempts across the workers and writes every address that starts
// with prefix to <out>/matches.jsonl, as {"address", "private_key"} lines (private_key is the
// 64-byte ed25519 key in hex). The benchmark kit times this run from outside and checks every
// match, so the attempts must be real Algorand accounts made from secure random seeds.
func runBench(prefix string, workers int, count uint64, outDir string) {
	if outDir == "" {
		fmt.Fprintln(os.Stderr, "-out is required with -count")
		os.Exit(2)
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(workers)

	var next uint64
	var mu sync.Mutex
	var lines []string
	var wg sync.WaitGroup
	const chunk = 1024
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var local []string
			for {
				end := atomic.AddUint64(&next, chunk)
				start := end - chunk
				if start >= count {
					break
				}
				if end > count {
					end = count
				}
				for i := start; i < end; i++ {
					acc := crypto.GenerateAccount()
					addr := acc.Address.String()
					if strings.HasPrefix(addr, prefix) {
						b, _ := json.Marshal(map[string]string{"address": addr, "private_key": hex.EncodeToString(acc.PrivateKey)})
						local = append(local, string(b))
					}
				}
			}
			mu.Lock()
			lines = append(lines, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	if err := os.WriteFile(filepath.Join(outDir, "matches.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	res, _ := json.Marshal(map[string]any{"attempts": count, "prefix": prefix, "matches": len(lines)})
	if err := os.WriteFile(filepath.Join(outDir, "result.json"), res, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
