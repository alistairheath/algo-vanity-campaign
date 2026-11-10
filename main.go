package main

import (
	"context"
	//"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/algorand/go-algorand-sdk/crypto"
	"github.com/algorand/go-algorand-sdk/mnemonic"
)

func worker(ctx context.Context, wg *sync.WaitGroup, prefix string, batch int, globalAttempts *uint64, found *uint32, resultChan chan<- crypto.Account) {
	defer wg.Done()

	local := 0
	for {
		// Check for cancellation / found
		select {
		case <-ctx.Done():
			// flush
			if local > 0 {
				atomic.AddUint64(globalAttempts, uint64(local))
			}
			return
		default:
		}

		// Generate an Algorand account (crypto.GenerateAccount)
		acc := crypto.GenerateAccount()
		local++

		// Convert address to string and check prefix
		addrStr := acc.Address.String()
		if strings.HasPrefix(addrStr, prefix) {
			// publish result (first one wins)
			// We attempt to set found flag atomically. If we succeed, send result.
			if atomic.CompareAndSwapUint32(found, 0, 1) {
				// send result (non-blocking with context check)
				select {
				case resultChan <- acc:
				case <-ctx.Done():
				}
				// flush local
				if local > 0 {
					atomic.AddUint64(globalAttempts, uint64(local))
				}
				return
			} else {
				// someone else found it; stop
				if local > 0 {
					atomic.AddUint64(globalAttempts, uint64(local))
				}
				return
			}
		}

		// Flush local counter periodically to reduce contention
		if local >= batch {
			atomic.AddUint64(globalAttempts, uint64(local))
			local = 0
		}
	}
}

func main() {
	// CLI flags
	var prefix string
	var workers int
	var batch int
	var printInterval float64
	var count uint64
	var outDir string

	flag.StringVar(&prefix, "prefix", "", "Prefix to search for (case-sensitive). Example: DIIISCO")
	flag.IntVar(&workers, "workers", 0, "Number of worker goroutines (default: number of CPUs)")
	flag.IntVar(&batch, "batch", 1000, "Local attempts before flushing to global counter")
	flag.Float64Var(&printInterval, "interval", 1.0, "Status print interval in seconds")
	flag.Uint64Var(&count, "count", 0, "Benchmark mode: stop after this many attempts and write matches to -out")
	flag.StringVar(&outDir, "out", "", "Benchmark mode: directory for matches.jsonl and result.json")
	flag.Parse()

	if prefix == "" {
		fmt.Println("Usage: go run main.go -prefix=AJH [-workers=8] [-batch=1000] [-interval=1.0]")
		os.Exit(1)
	}

	if count > 0 {
		runBench(prefix, workers, count, outDir)
		return
	}

	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(workers)

	fmt.Printf("Searching for prefix=%q using %d workers (batch=%d, interval=%.2fs)\n", prefix, workers, batch, printInterval)

	var globalAttempts uint64 = 0
	var found uint32 = 0
	resultChan := make(chan crypto.Account, 1)

	// Context to cancel workers when found
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, prefix, batch, &globalAttempts, &found, resultChan)
	}

	// Printer ticker
	ticker := time.NewTicker(time.Duration(printInterval*1000) * time.Millisecond)
	defer ticker.Stop()
	start := time.Now()
	var last uint64 = 0

loop:
	for {
		select {
		case acc := <-resultChan:
			// We have a result — cancel workers and print
			cancel()
			// Wait for workers to exit (they will flush local counters)
			wg.Wait()
			total := atomic.LoadUint64(&globalAttempts)
			elapsed := time.Since(start).Seconds()
			rate := float64(total) / elapsed
			fmt.Printf("\n---- FOUND! ----\n")
			fmt.Printf("Address: %s\n", acc.Address.String())

			// PrivateKey in Account is ed25519.PrivateKey (64 bytes: seed+pub) in SDK
			priv := acc.PrivateKey
			// Derive mnemonic from private key using SDK helper
			mn, err := mnemonic.FromPrivateKey(priv)
			if err != nil {
				fmt.Printf("mnemonic.FromPrivateKey error: %v\n", err)
			} else {
				fmt.Printf("Mnemonic: %s\n", mn)
			}

			// Print private key hex (seed+pub). If you want only seed (32 bytes), derive accordingly.
			fmt.Printf("PrivateKey (hex): %s\n", hex.EncodeToString(priv))
			fmt.Printf("Total attempts: %d\n", total)
			fmt.Printf("Elapsed: %.2fs, Avg rate: %.2f/s\n", elapsed, rate)
			break loop

		case <-ticker.C:
			total := atomic.LoadUint64(&globalAttempts)
			delta := total - last
			elapsed := time.Since(start).Seconds()
			rate := float64(total) / elapsed
			fmt.Printf("[%.1fs] Attempts: %12d (Δ%8d)  Rate: %10.2f/s\n", elapsed, total, delta, rate)
			last = total

			// quick stop if someone externally set found (rare)
			if atomic.LoadUint32(&found) != 0 {
				cancel()
			}
		case <-ctx.Done():
			// cancelled externally
			break loop
		}
	}

	// Ensure goroutines finished
	wg.Wait()
}
