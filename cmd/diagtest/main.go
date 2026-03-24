package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	fmt.Printf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	paths := []struct{ dir, mask string }{
		{`C:\Windows\System32\config`, "SYSTEM"},
		{`C:\Windows\System32\config`, "SAM"},
		{`C:\Windows\System32\config`, "SOFTWARE"},
		{`C:\Windows\System32\config`, "SECURITY"},
		{`C:\Windows\System32\winevt\logs`, "*.evtx"},
	}

	for _, p := range paths {
		fmt.Printf("=== %s / %s ===\n", p.dir, p.mask)

		entries, err := os.ReadDir(p.dir)
		if err != nil {
			fmt.Printf("  ReadDir: FAIL - %v\n", err)
		} else {
			count := 0
			for _, e := range entries {
				matched, _ := filepath.Match(p.mask, e.Name())
				if matched {
					count++
				}
			}
			fmt.Printf("  ReadDir: %d total, %d matched\n", len(entries), count)
		}

		matches, _ := filepath.Glob(filepath.Join(p.dir, p.mask))
		fmt.Printf("  Glob: %d matches\n", len(matches))

		if p.mask != "*.evtx" {
			f := filepath.Join(p.dir, p.mask)
			_, err := os.Stat(f)
			if err != nil {
				fmt.Printf("  Stat: FAIL - %v\n", err)
			} else {
				fmt.Printf("  Stat: OK\n")
			}
		}
		fmt.Println()
	}
}
