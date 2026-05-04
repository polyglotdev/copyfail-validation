// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package procscan_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/procscan"
)

// ExampleScan demonstrates the typical caller pattern: invoke Scan
// with a signal-aware context, then triage the result against the two
// documented sentinels (ErrNotRoot, ErrProcMissing) before consuming
// the populated ScanResult. The triage shape mirrors spec §11:
// ErrNotRoot becomes a Skip with reason "requires root to enumerate
// /proc/<pid>/maps for processes other than self", ErrProcMissing
// becomes an Error result, anything else means the scan ran.
//
// This example is intentionally compiled but NOT run by `go test`
// (no `// Output:` directive) because the visible behavior depends on
// the caller's EUID — `go test` may be unprivileged or root depending
// on the CI environment, so a pinned Output line would be flaky. The
// runnable, root-independent Output assertions live on the companion
// examples (Example_scanResult_iteration, ExampleAFAlgModules,
// ExampleErrNotRoot, ExampleErrProcMissing).
func ExampleScan() {
	// Real CLI invocations use a signal-aware context (e.g.,
	// signal.NotifyContext) so Ctrl-C cleanly aborts the scan
	// between PID iterations.
	ctx := context.Background()

	result, err := procscan.Scan(ctx)
	switch {
	case errors.Is(err, procscan.ErrNotRoot):
		fmt.Println("skip: scan requires root")
	case errors.Is(err, procscan.ErrProcMissing):
		fmt.Println("error: /proc not mounted")
	case err != nil:
		fmt.Printf("error: %v\n", err)
	case len(result.Candidates) == 0:
		fmt.Printf("pass: %d processes scanned, none flagged\n", result.ScannedPIDs)
	default:
		fmt.Printf("fail: %d candidate process(es) of %d scanned\n", len(result.Candidates), result.ScannedPIDs)
	}
}

// Example_scanResult_iteration shows the consumer-facing shape of a
// populated ScanResult. Real code receives this struct from Scan;
// here it is hand-built so the example is hermetic and godoc can
// verify exact output bytes. Iteration order is by PID ascending —
// the package guarantees this so audit log diffs are stable across
// runs.
func Example_scanResult_iteration() {
	result := procscan.ScanResult{
		ScannedPIDs:    412,
		UnreadablePIDs: []int{42, 73},
		Candidates: []procscan.Candidate{
			{
				PID:         1817,
				Comm:        "encfs",
				MatchReason: "algif_aead in /proc/1817/maps",
			},
		},
	}

	fmt.Printf("scanned=%d unreadable=%d\n", result.ScannedPIDs, len(result.UnreadablePIDs))
	for _, c := range result.Candidates {
		fmt.Printf("pid=%d comm=%s reason=%s\n", c.PID, c.Comm, c.MatchReason)
	}
	// Output:
	// scanned=412 unreadable=2
	// pid=1817 comm=encfs reason=algif_aead in /proc/1817/maps
}

// ExampleAFAlgModules shows the contents of the AF_ALG-family
// allowlist that drives Scan's substring matching. Callers building
// their own ad-hoc scanners outside this package should iterate the
// same slice so additions made through security review propagate
// without code changes downstream.
func ExampleAFAlgModules() {
	for _, mod := range procscan.AFAlgModules {
		fmt.Println(mod)
	}
	// Output:
	// af_alg
	// algif_aead
	// algif_skcipher
	// algif_hash
	// algif_rng
}

// ExampleCandidate shows the field shape one Candidate carries. Comm
// is the short executable name from /proc/<pid>/comm (kernel
// TASK_COMM_LEN limit, no path), and MatchReason combines the matched
// module name, the maps file path, and the matching maps line so an
// operator can re-run the inspection by hand.
func ExampleCandidate() {
	c := procscan.Candidate{
		PID:         1817,
		Comm:        "encfs",
		MatchReason: "algif_aead in /proc/1817/maps: 7f8b00010000-7f8b00020000 r-xp 00000000 00:01 67890 /lib/modules/6.1.0/kernel/crypto/algif_aead.ko",
	}
	fmt.Printf("pid=%d comm=%s\n", c.PID, c.Comm)
	fmt.Printf("reason starts with: %s\n", c.MatchReason[:33])
	// Output:
	// pid=1817 comm=encfs
	// reason starts with: algif_aead in /proc/1817/maps: 7f
}

// ExampleScanResult shows the zero value's safe iteration shape. The
// package promises Candidates and UnreadablePIDs are non-nil empty
// slices in a populated result, but a hand-built zero value has nil
// slices — both forms are safe to range-over in Go, so consumers can
// uniformly iterate without a length check.
func ExampleScanResult() {
	r := procscan.ScanResult{}
	fmt.Printf("scanned=%d unreadable=%d candidates=%d\n", r.ScannedPIDs, len(r.UnreadablePIDs), len(r.Candidates))
	// Output:
	// scanned=0 unreadable=0 candidates=0
}

// ExampleErrNotRoot shows the canonical errors.Is matching pattern
// that callers use to translate the EUID precondition failure into a
// Skip in the upstream check.
func ExampleErrNotRoot() {
	err := procscan.ErrNotRoot
	if errors.Is(err, procscan.ErrNotRoot) {
		fmt.Println("matched ErrNotRoot via errors.Is")
	}
	// Output:
	// matched ErrNotRoot via errors.Is
}

// ExampleErrProcMissing shows the canonical errors.Is matching pattern
// for the /proc-not-mounted case. Callers translate this into an
// Error result rather than a Skip — a missing /proc on a host the
// validator was asked to inspect is a hard failure, not a documented
// degradation.
func ExampleErrProcMissing() {
	err := procscan.ErrProcMissing
	if errors.Is(err, procscan.ErrProcMissing) {
		fmt.Println("matched ErrProcMissing via errors.Is")
	}
	// Output:
	// matched ErrProcMissing via errors.Is
}
