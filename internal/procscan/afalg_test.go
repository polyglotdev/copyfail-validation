// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package procscan_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/procscan"
)

// pidFile is a single test-fixture file under a fake /proc/<pid>/ dir.
// The path is relative to the PID directory ("maps" or "comm"); content
// is written verbatim. modeSet=true selects an explicit on-disk
// permission bits value (use mode=0o000 to simulate EACCES); modeSet=false
// uses the default 0o644 — a tri-state is needed because Go's zero
// value 0o000 is itself a meaningful permission bit pattern that we
// must distinguish from "caller did not set a mode".
type pidFile struct {
	path    string
	content string
	mode    os.FileMode
	modeSet bool
}

// pidFixture describes one /proc/<pid>/ directory: the numeric PID
// component of the directory name, plus the files to write inside it.
// Omitting a "maps" entry from files models the documented spec §11
// race where a process exited between the parent ReadDir and the
// per-PID ReadFile — same ENOENT code path, no test-process
// interleaving needed to reproduce it.
//
// Field order is laid out for govet's fieldalignment pass: slice
// header first, scalar last.
type pidFixture struct {
	files []pidFile
	pid   int
}

// procFixture is a complete fake /proc tree: a list of /proc/<pid>/
// directories plus a list of non-PID names to create at the top level
// (e.g., "kpageflags", "self", "meminfo") so the PID-name filter is
// exercised against real entries rather than only its own unit.
type procFixture struct {
	pids       []pidFixture
	extraNames []string
}

// buildProcFixture materializes f under a fresh t.TempDir() and returns
// the absolute path. It always creates a "self" entry as a regular file
// (not a symlink — symlinks behave inconsistently across temp-dir
// implementations and self-as-file still satisfies the os.Stat
// precondition probe inside scanWithRoot).
func buildProcFixture(subT *testing.T, f procFixture) string {
	subT.Helper()
	root := subT.TempDir()

	// Always create /proc/self so the precondition probe in
	// scanWithRoot succeeds. Tests that want to exercise the
	// ErrProcMissing path should NOT use this helper; they use
	// t.TempDir() directly and never write a "self" entry.
	if err := os.WriteFile(filepath.Join(root, "self"), []byte("self-marker"), 0o600); err != nil {
		subT.Fatalf("write self marker: %v", err)
	}

	for _, name := range f.extraNames {
		// Every extra name is a regular file. /proc has both files
		// (meminfo) and directories (self, bus, fs) at its top level
		// in reality, but for the PID-name filter the only thing that
		// matters is whether the name parses as a PID — directory vs.
		// file does not. Files are simpler to create.
		if err := os.WriteFile(filepath.Join(root, name), []byte("not-a-pid"), 0o600); err != nil {
			subT.Fatalf("write extra %q: %v", name, err)
		}
	}

	for _, pf := range f.pids {
		pidDir := filepath.Join(root, strconv.Itoa(pf.pid))
		if err := os.MkdirAll(pidDir, 0o750); err != nil {
			subT.Fatalf("mkdir %s: %v", pidDir, err)
		}
		for _, file := range pf.files {
			full := filepath.Join(pidDir, file.path)
			mode := os.FileMode(0o644)
			if file.modeSet {
				mode = file.mode
			}
			if err := os.WriteFile(full, []byte(file.content), mode); err != nil {
				subT.Fatalf("write %s: %v", full, err)
			}
			// os.WriteFile only honors the mode argument when
			// creating the file. We always create here, but on some
			// umask configurations the resulting mode can still be
			// masked. An explicit chmod restores the requested bits
			// so the EACCES simulation is reliable across hosts.
			if file.modeSet {
				if err := os.Chmod(full, mode); err != nil {
					subT.Fatalf("chmod %s: %v", full, err)
				}
				// Register a cleanup that re-permits the file so
				// t.TempDir's removal does not fail with EACCES on
				// the inner directory traversal.
				subT.Cleanup(func() {
					_ = os.Chmod(full, 0o600)
				})
			}
		}
	}

	return root
}

// mustCallScanWithRoot is the test-side accessor for the unexported
// scanWithRoot. The exported Scan refuses to run unless EUID==0, which
// is not the typical CI environment, so every behavioral test goes
// through this entry point. The function is deliberately defined at
// package level (not inside each test) so the export_test.go indirection
// has exactly one definition — golangci-lint's `unused` linter would
// flag a per-test wrapper that is never reused.
func mustCallScanWithRoot(subT *testing.T, ctx context.Context, root string) (procscan.ScanResult, error) {
	subT.Helper()
	return procscan.ScanWithRootForTest(ctx, root)
}

// TestScanWithRoot covers the full /proc walker contract: clean fixtures,
// matched modules across multiple PIDs, EACCES handling, ENOENT mid-scan
// races, non-PID name filtering, empty /proc trees, and context
// cancellation. Sub-tests run in parallel because each builds its own
// t.TempDir() — there is no shared mutable state.
func TestScanWithRoot(t *testing.T) {
	t.Parallel()

	const innocuousLine = "7f8b00000000-7f8b00010000 r-xp 00000000 00:01 12345 /lib/x86_64-linux-gnu/libc.so.6\n"
	const algifAeadLine = "7f8b00010000-7f8b00020000 r-xp 00000000 00:01 67890 /lib/modules/6.1.0/kernel/crypto/algif_aead.ko\n"
	const algifSkcipherLine = "7f8b00020000-7f8b00030000 r-xp 00000000 00:01 11111 /lib/modules/6.1.0/kernel/crypto/algif_skcipher.ko\n"

	tests := []struct {
		fixtureFn      func(subT *testing.T) string
		wantErrIs      error
		name           string
		wantUnreadable []int
		wantCandidates []procscan.Candidate
		wantScanned    int
	}{
		{
			name: "empty proc has zero scanned and zero candidates",
			fixtureFn: func(subT *testing.T) string {
				return buildProcFixture(subT, procFixture{})
			},
			wantScanned:    0,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{},
		},
		{
			name: "clean fixture with two pids and no algif strings",
			fixtureFn: func(subT *testing.T) string {
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 1,
							files: []pidFile{
								{path: "maps", content: innocuousLine},
								{path: "comm", content: "init\n"},
							},
						},
						{
							pid: 1817,
							files: []pidFile{
								{path: "maps", content: innocuousLine},
								{path: "comm", content: "sshd\n"},
							},
						},
					},
				})
			},
			wantScanned:    2,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{},
		},
		{
			name: "non-PID entries do not contribute to ScannedPIDs",
			fixtureFn: func(subT *testing.T) string {
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 1,
							files: []pidFile{
								{path: "maps", content: innocuousLine},
								{path: "comm", content: "init\n"},
							},
						},
					},
					extraNames: []string{"meminfo", "kpageflags", "cmdline", "filesystems"},
				})
			},
			wantScanned:    1,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{},
		},
		{
			name: "single process with algif_aead emits one candidate",
			fixtureFn: func(subT *testing.T) string {
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 1817,
							files: []pidFile{
								{path: "maps", content: innocuousLine + algifAeadLine},
								{path: "comm", content: "encfs\n"},
							},
						},
					},
				})
			},
			wantScanned:    1,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{
				{
					PID:         1817,
					Comm:        "encfs",
					MatchReason: "algif_aead", // substring assertion below; full reason includes the maps path.
				},
			},
		},
		{
			name: "two flagged processes are returned in PID order",
			fixtureFn: func(subT *testing.T) string {
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 1817,
							files: []pidFile{
								{path: "maps", content: innocuousLine + algifAeadLine},
								{path: "comm", content: "encfs\n"},
							},
						},
						{
							pid: 100,
							files: []pidFile{
								{path: "maps", content: algifSkcipherLine},
								{path: "comm", content: "vpn-daemon\n"},
							},
						},
					},
				})
			},
			wantScanned:    2,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{
				{PID: 100, Comm: "vpn-daemon", MatchReason: "algif_skcipher"},
				{PID: 1817, Comm: "encfs", MatchReason: "algif_aead"},
			},
		},
		{
			name: "EACCES on maps is recorded in UnreadablePIDs",
			fixtureFn: func(subT *testing.T) string {
				if os.Geteuid() == 0 {
					subT.Skip("root bypasses the chmod 0o000 EACCES simulation")
				}
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 4242,
							files: []pidFile{
								{path: "maps", content: innocuousLine, mode: 0o000, modeSet: true},
								{path: "comm", content: "secret-daemon\n"},
							},
						},
					},
				})
			},
			wantScanned:    1,
			wantUnreadable: []int{4242},
			wantCandidates: []procscan.Candidate{},
		},
		{
			name: "process exited mid-scan (ENOENT on maps) is silently skipped",
			fixtureFn: func(subT *testing.T) string {
				// Simulate the race where the parent ReadDir saw
				// /proc/9999, but by the time we ReadFile
				// /proc/9999/maps the process has exited and the
				// file is gone. We model this by creating a PID
				// directory whose maps file is missing — same
				// ENOENT code path as a real exit race. The PID
				// directory itself is still present so the parent
				// ReadDir produces the entry, exercising the
				// silent-skip branch in scanWithRoot.
				return buildProcFixture(subT, procFixture{
					pids: []pidFixture{
						{
							pid: 9999,
							files: []pidFile{
								// no "maps" file — the per-PID
								// ReadFile will return ENOENT.
								{path: "comm", content: "ghost\n"},
							},
						},
						{
							pid: 1,
							files: []pidFile{
								{path: "maps", content: innocuousLine},
								{path: "comm", content: "init\n"},
							},
						},
					},
				})
			},
			// Both PID dirs appear in the parent ReadDir (so each
			// counts as a scanned attempt), but PID 9999's missing
			// maps is silently skipped — it is NOT recorded in
			// UnreadablePIDs and NOT reported as a Candidate.
			wantScanned:    2,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{},
		},
		{
			name: "missing /proc returns ErrProcMissing",
			fixtureFn: func(subT *testing.T) string {
				// Use an empty TempDir WITHOUT calling
				// buildProcFixture (which always creates "self").
				// This is the only path that exercises
				// ErrProcMissing.
				return subT.TempDir()
			},
			wantScanned:    0,
			wantUnreadable: []int{},
			wantCandidates: []procscan.Candidate{},
			wantErrIs:      procscan.ErrProcMissing,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			root := tc.fixtureFn(subT)
			result, err := mustCallScanWithRoot(subT, context.Background(), root)

			switch {
			case tc.wantErrIs == nil && err != nil:
				subT.Fatalf("scanWithRoot() unexpected error: %v", err)
			case tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs):
				subT.Fatalf("scanWithRoot() error = %v; want errors.Is(_, %v)", err, tc.wantErrIs)
			}

			if got, want := result.ScannedPIDs, tc.wantScanned; got != want {
				subT.Errorf("ScannedPIDs = %d; want %d", got, want)
			}
			if diff := cmp.Diff(tc.wantUnreadable, result.UnreadablePIDs); diff != "" {
				subT.Errorf("UnreadablePIDs mismatch (-want +got):\n%s", diff)
			}

			if len(result.Candidates) != len(tc.wantCandidates) {
				subT.Fatalf("Candidates len = %d; want %d (got %#v)", len(result.Candidates), len(tc.wantCandidates), result.Candidates)
			}
			for i, want := range tc.wantCandidates {
				got := result.Candidates[i]
				if got.PID != want.PID {
					subT.Errorf("Candidates[%d].PID = %d; want %d", i, got.PID, want.PID)
				}
				if got.Comm != want.Comm {
					subT.Errorf("Candidates[%d].Comm = %q; want %q", i, got.Comm, want.Comm)
				}
				if !strings.Contains(got.MatchReason, want.MatchReason) {
					subT.Errorf("Candidates[%d].MatchReason = %q; want substring %q", i, got.MatchReason, want.MatchReason)
				}
			}
		})
	}
}

// TestScanWithRoot_MatchReasonShape pins the human-readable shape of
// MatchReason: it MUST include the matched module name, the maps file
// path (so an operator can re-read the same file by hand), and the
// matching line (so the operator knows WHY the substring matched even
// when the module name appears in multiple plausible contexts). Without
// this guarantee the audit evidence is just "PID flagged", which is
// useless for triage.
func TestScanWithRoot_MatchReasonShape(t *testing.T) {
	t.Parallel()

	const algifLine = "7f8b00010000-7f8b00020000 r-xp 00000000 00:01 67890 /lib/modules/6.1.0/kernel/crypto/algif_aead.ko"
	root := buildProcFixture(t, procFixture{
		pids: []pidFixture{
			{
				pid: 1817,
				files: []pidFile{
					{path: "maps", content: algifLine + "\n"},
					{path: "comm", content: "encfs\n"},
				},
			},
		},
	})

	result, err := mustCallScanWithRoot(t, context.Background(), root)
	if err != nil {
		t.Fatalf("scanWithRoot() error = %v", err)
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("expected exactly one candidate; got %d", len(result.Candidates))
	}

	reason := result.Candidates[0].MatchReason
	wantSubstrings := []string{
		"algif_aead",
		filepath.Join(root, "1817", "maps"),
		algifLine,
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(reason, want) {
			t.Errorf("MatchReason missing %q substring; full value:\n%s", want, reason)
		}
	}
}

// TestScanWithRoot_ContextCancellation verifies the partial-result
// contract: when ctx is canceled between iterations, Scan returns the
// partial ScanResult collected so far PLUS a wrapped ctx.Err(). A nil
// error after cancellation would be a bug — callers want to know the
// audit is incomplete so they can re-run instead of trusting partial
// data.
func TestScanWithRoot_ContextCancellation(t *testing.T) {
	t.Parallel()

	root := buildProcFixture(t, procFixture{
		pids: []pidFixture{
			{
				pid: 1,
				files: []pidFile{
					{path: "maps", content: "ignored"},
					{path: "comm", content: "init\n"},
				},
			},
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel BEFORE Scan runs so the first iteration check trips.

	result, err := mustCallScanWithRoot(t, ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("scanWithRoot() error = %v; want errors.Is(_, context.Canceled)", err)
	}
	if result.ScannedPIDs != 0 {
		t.Errorf("ScannedPIDs = %d; want 0 (cancellation should fire before any work)", result.ScannedPIDs)
	}
	if len(result.Candidates) != 0 {
		t.Errorf("Candidates len = %d; want 0", len(result.Candidates))
	}
}

// TestScan_NotRoot verifies that the production entry point Scan
// refuses to run when EUID != 0. CI runs almost always satisfy this
// precondition (test jobs run as a normal user); root-running
// CI environments are a documented edge case that defeats the
// simulation but does NOT cause a wrong test outcome — the test simply
// asserts a property of the package's public contract that holds
// independent of root status.
func TestScan_NotRoot(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("test asserts the EUID!=0 branch; cannot exercise it as root")
	}

	_, err := procscan.Scan(context.Background())
	if !errors.Is(err, procscan.ErrNotRoot) {
		t.Fatalf("Scan() error = %v; want errors.Is(_, ErrNotRoot)", err)
	}
}

// TestAFAlgModules_HasExpectedFamily pins the contents of the
// AFAlgModules allowlist. Adding a new entry should require a deliberate
// change here AND a security-review notation in the package doc — this
// test is the build-failing tripwire that catches an accidental
// addition (or removal) made without updating the spec.
func TestAFAlgModules_HasExpectedFamily(t *testing.T) {
	t.Parallel()

	want := []string{
		"af_alg",
		"algif_aead",
		"algif_skcipher",
		"algif_hash",
		"algif_rng",
	}
	if diff := cmp.Diff(want, procscan.AFAlgModules); diff != "" {
		t.Errorf("AFAlgModules mismatch (-want +got):\n%s", diff)
	}
}
