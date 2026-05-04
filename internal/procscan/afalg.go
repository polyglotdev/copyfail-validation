// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package procscan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Sentinel errors returned by this package. Callers MUST match with
// errors.Is rather than string comparison — error messages are not part
// of the package's API contract and may change between minor releases.
var (
	// ErrNotRoot is returned by Scan when the process EUID is non-zero.
	// Callers should translate this to a Skip with reason
	// "requires root to enumerate /proc/<pid>/maps for processes other
	// than self" (spec §11). The kernel hides foreign-UID process
	// directories from non-root readers, so a non-root scan would
	// produce a misleadingly empty result.
	ErrNotRoot = errors.New("procscan: scan requires EUID=0")

	// ErrProcMissing is returned when /proc is not mounted (typically a
	// minimal container with no /proc, or a non-Linux dev machine).
	// Callers should translate this to an Error result with the wrapped
	// message in Result.Err.
	ErrProcMissing = errors.New("procscan: /proc not readable")
)

// Candidate is one process flagged by Scan as having an AF_ALG-family
// module mapped. Comm is the executable name from /proc/<pid>/comm
// (subject to the kernel's 15-character TASK_COMM_LEN limit, no path
// component); MatchReason is a human-readable description of WHY this
// process was flagged — the matching module name and the maps line that
// triggered the match, so an operator running the audit later has the
// forensic detail needed to re-run the inspection by hand.
//
// Field order is laid out for govet's fieldalignment pass: string
// headers and slice headers first, fixed-width integers last.
type Candidate struct {
	// Comm is the executable name from /proc/<pid>/comm. The kernel
	// truncates this to TASK_COMM_LEN (16 bytes including the trailing
	// newline) so values may be shorter than the binary's full name.
	// Empty when /proc/<pid>/comm could not be read (e.g., process
	// exited between the maps read and the comm read).
	Comm string

	// MatchReason is a human-readable description: the matching module
	// name, the literal maps line, and the source path so the evidence
	// is self-contained. Format is not part of the package contract;
	// callers should treat it as opaque text for display.
	MatchReason string

	// PID is the process identifier from the /proc/<pid>/ directory
	// name. Always > 0 for emitted Candidates.
	PID int
}

// ScanResult is the return shape from Scan. ScannedPIDs is the count of
// /proc/<pid>/ entries the walker successfully iterated (it counts
// every PID directory the walker attempted to read, including ones
// whose maps were unreadable). UnreadablePIDs records PIDs whose
// /proc/<pid>/maps returned EACCES — these are processes the validator
// could not inspect, typically because they run as a different non-root
// user under a more restrictive LSM policy (the EUID check that gates
// Scan does not guarantee read access to every /proc/<pid>/maps file).
// Candidates is the flagged set; empty (NOT nil) when no process was
// flagged so callers can iterate without a length check.
//
// Field order is laid out for govet's fieldalignment pass: slice
// headers first, scalar last.
type ScanResult struct {
	// UnreadablePIDs is the list of PIDs whose /proc/<pid>/maps could
	// not be read because of EACCES. Sorted ascending for deterministic
	// audit output.
	UnreadablePIDs []int

	// Candidates is the list of processes flagged as AF_ALG-family
	// users. Empty (NOT nil) when no process matched, sorted by PID
	// ascending so audit log diffs are stable across runs.
	Candidates []Candidate

	// ScannedPIDs is the count of /proc/<pid>/ entries the walker
	// successfully iterated. It includes PIDs whose maps were
	// unreadable (the directory itself was visible) but excludes
	// non-PID entries like /proc/meminfo or /proc/self.
	ScannedPIDs int
}

// Scan walks /proc/[0-9]*/, reads each /proc/<pid>/maps, and flags any
// process whose maps contains an entry matching one of AFAlgModules.
//
// Preconditions (checked before the walk):
//
//   - os.Geteuid() == 0 — otherwise returns ErrNotRoot.
//   - /proc/self is readable — otherwise returns ErrProcMissing.
//
// Algorithm (see spec §11 for the full contract):
//
//  1. ReadDir /proc; filter to entries whose name parses as a positive
//     integer (skips meminfo, kpageflags, self, etc.).
//  2. For each PID, ReadFile /proc/<pid>/maps.
//     On EACCES → record in UnreadablePIDs, continue.
//     On ENOENT → process exited mid-scan, ignore silently.
//     Other errors → continue to the next PID (do NOT abort the scan;
//     an audit run wants the full picture).
//  3. Scan the maps content for any AFAlgModules entry as a literal
//     substring match against the pathname column of each line. On
//     match, ReadFile /proc/<pid>/comm and emit a Candidate with the
//     matched module name and the matching maps line.
//
// The function honors ctx.Done() between PID iterations; on cancellation
// it returns the partial ScanResult plus a wrapped ctx.Err().
//
// Output ordering: Candidates and UnreadablePIDs are sorted by PID
// ascending so repeated runs against the same host produce
// byte-identical audit evidence (modulo actual host changes).
func Scan(ctx context.Context) (ScanResult, error) {
	if os.Geteuid() != 0 {
		return ScanResult{
			UnreadablePIDs: []int{},
			Candidates:     []Candidate{},
		}, ErrNotRoot
	}
	return scanWithRoot(ctx, "/proc")
}

// scanWithRoot is the testable core of Scan. Production code calls
// Scan, which checks the EUID and then delegates here with procRoot =
// "/proc". Tests call this function directly with a t.TempDir()
// populated with a fake /proc tree so coverage doesn't require root.
//
// procRoot is the directory the walker reads as if it were /proc;
// /proc/<pid>/maps becomes <procRoot>/<pid>/maps and so on.
func scanWithRoot(ctx context.Context, procRoot string) (ScanResult, error) {
	result := ScanResult{
		UnreadablePIDs: []int{},
		Candidates:     []Candidate{},
	}

	// Precondition: /proc must exist. We probe procRoot/self because
	// that is what spec §11 specifies and it is the same probe the
	// caller's check phase will use; missing /proc/self with /proc
	// itself present would still indicate a non-functional /proc and
	// must not be treated as a successful empty scan.
	if _, err := os.Stat(filepath.Join(procRoot, "self")); err != nil {
		return result, fmt.Errorf("procscan: stat %s/self: %w: %w", procRoot, ErrProcMissing, err)
	}

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return result, fmt.Errorf("procscan: read dir %s: %w", procRoot, err)
	}

	// Collect the PID list first so we can iterate in deterministic
	// order. ReadDir already returns sorted entries on Linux, but
	// sorting numerically (1, 2, 10, 1817) instead of lexicographically
	// (1, 10, 1817, 2) is friendlier for audit output.
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		pid, ok := pidFromName(e.Name())
		if !ok {
			continue
		}
		// We do not call e.Type() / e.IsDir() here: a /proc/<pid> entry
		// is always a directory in a real /proc. The downstream
		// ReadFile will surface an error if a test fixture is malformed
		// (e.g., a regular file named "1234"), and that error path is
		// already covered.
		pids = append(pids, pid)
	}
	sort.Ints(pids)

	for _, pid := range pids {
		// Honor cancellation BETWEEN iterations rather than attempting
		// to interrupt an in-flight ReadFile. Per-PID work is cheap
		// (single ReadFile call), so the cancellation latency is
		// bounded by one /proc/<pid>/maps read.
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("procscan: scan canceled at pid %d: %w", pid, err)
		}

		result.ScannedPIDs++

		mapsPath := filepath.Join(procRoot, strconv.Itoa(pid), "maps")
		mapsContent, err := os.ReadFile(mapsPath) // #nosec G304 -- procRoot is hard-coded /proc in production; tests pass t.TempDir().
		if err != nil {
			switch {
			case errors.Is(err, fs.ErrNotExist):
				// Process exited between the ReadDir and the ReadFile.
				// This is the documented race in spec §11 — silently
				// skip; ScannedPIDs already counted the attempt.
				continue
			case errors.Is(err, fs.ErrPermission):
				result.UnreadablePIDs = append(result.UnreadablePIDs, pid)
				continue
			default:
				// Any other error (I/O failure, malformed fixture)
				// is logged into the audit trail by way of an
				// UnreadablePIDs entry — we do not abort the whole
				// scan because the audit needs the full picture
				// (see package doc on result completeness).
				result.UnreadablePIDs = append(result.UnreadablePIDs, pid)
				continue
			}
		}

		matchedModule, matchedLine, ok := findAFAlgMatch(mapsContent)
		if !ok {
			continue
		}

		comm := readComm(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
		result.Candidates = append(result.Candidates, Candidate{
			PID:         pid,
			Comm:        comm,
			MatchReason: fmt.Sprintf("%s in %s: %s", matchedModule, mapsPath, matchedLine),
		})
	}

	// Sort UnreadablePIDs (Candidates are already PID-ordered because
	// we iterate in PID order). Defensive: sort.Ints is cheap and
	// guarantees the audit-stable shape promised in the field doc.
	sort.Ints(result.UnreadablePIDs)

	return result, nil
}

// pidFromName parses a /proc directory entry name as a positive PID.
// Returns (pid, true) for names that are entirely decimal digits and
// represent a value > 0; returns (_, false) for everything else
// (meminfo, kpageflags, self, "0" — kernel never emits PID 0 — and
// any name containing non-digit characters).
//
// strconv.Atoi alone would accept leading "+", whitespace, and "-0"
// which are not valid /proc directory names; an explicit digit check
// rejects those and also rules out negative values without an extra
// branch.
func pidFromName(name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// findAFAlgMatch returns the first AFAlgModules name found as a
// substring of any line in maps, the matching line, and ok=true. If no
// AFAlgModules name appears anywhere in maps, returns ("", "", false).
//
// Substring match (not word-boundary match) is intentional: kernel
// module paths in /proc/<pid>/maps appear in a few different shapes
// across kernel versions and module-loading paths (full .ko path
// "/lib/modules/.../algif_aead.ko", basename only, or the
// "[algif_aead]" pseudo-name for some builtins) and a literal
// substring match handles all of them with one simple rule.
//
// The line returned is the literal maps line WITHOUT the trailing
// newline so the MatchReason format does not embed newlines in the
// audit-log output.
func findAFAlgMatch(maps []byte) (string, string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(maps))
	// /proc/<pid>/maps lines fit comfortably in the default 64KiB
	// scanner buffer (the path is the only variable-length column and
	// kernel paths are bounded by PATH_MAX = 4096 in practice). We do
	// NOT raise the buffer because doing so would invite OOM if a
	// hostile fixture streams an arbitrarily long single "line".
	for scanner.Scan() {
		line := scanner.Text()
		for _, mod := range AFAlgModules {
			if strings.Contains(line, mod) {
				return mod, line, true
			}
		}
	}
	// scanner.Err is intentionally ignored here: the caller already
	// has the full maps bytes (we read them with ReadFile), so a
	// scanner error during re-parsing means the bytes were
	// pathologically shaped (single >64KiB "line"). Treating that as
	// "no match" rather than fatal preserves the result-completeness
	// invariant in the package doc — one weird process must not abort
	// the whole audit.
	return "", "", false
}

// readComm returns the contents of /proc/<pid>/comm, trimmed of any
// trailing newline (the kernel always appends one). Returns "" on any
// I/O error so the caller can still emit a Candidate; the comm field
// is best-effort context, not a correctness requirement.
//
// The kernel limits TASK_COMM_LEN to 16 bytes including the trailing
// newline, so a successful read is at most 15 visible characters. We
// do not trim further than TrimSpace (which handles the newline plus
// any defensive whitespace) to avoid masking a future kernel format
// change.
func readComm(path string) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path is built from procRoot + pid, both validated above.
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}
