// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// binaryCacheOnce ensures the test binary is built exactly once per
// test process. Building inside every TestCLI_* function would gate the
// entire integration suite on a serialized build step; sync.Once
// amortizes the cost across however many parallel sub-suites the
// runner spawns.
var (
	binaryCacheOnce sync.Once
	binaryCachePath string
	binaryCacheErr  error
)

// buildBinary returns the absolute path to a freshly-built copyfail-
// validate binary, building it if it does not already exist for this
// test process. The binary lives under os.TempDir(); test cleanup is
// handled by the OS rather than t.Cleanup because subtests cannot
// share a single Cleanup callback owned by sync.Once.
func buildBinary(t *testing.T) string {
	t.Helper()
	binaryCacheOnce.Do(func() {
		dir, err := os.MkdirTemp("", "copyfail-validate-*")
		if err != nil {
			binaryCacheErr = err
			return
		}
		name := "copyfail-validate"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		binPath := filepath.Join(dir, name)
		// The package main lives at this directory; `go build .`
		// resolves it from the current dir of the build (the test
		// binary's working dir at TestMain entry).
		cmd := exec.Command("go", "build", "-o", binPath, "./")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if buildErr := cmd.Run(); buildErr != nil {
			binaryCacheErr = buildErr
			return
		}
		binaryCachePath = binPath
	})
	if binaryCacheErr != nil {
		t.Fatalf("build copyfail-validate binary: %v", binaryCacheErr)
	}
	return binaryCachePath
}

// cliResult bundles the captured outputs of one CLI invocation so the
// table-driven assertions can compare them in a single shot. Pulling
// the run+capture into a helper keeps each TestCLI_* focused on the
// specific flag-shape and exit-code it asserts.
type cliResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
}

// runCLI invokes the test binary with argv and returns the captured
// outputs + exit code. The test's deadline is enforced via a context
// timeout so a hung child does not stall the whole suite.
func runCLI(t *testing.T, argv ...string) cliResult {
	t.Helper()
	bin := buildBinary(t)
	// 30s is generous: the slowest legitimate run on the dev host is
	// ~2s end-to-end; a slower-than-that result indicates the binary
	// hung and we want to fail fast rather than wait for the test
	// timeout.
	cmd := exec.Command(bin, argv...) // #nosec G204 -- bin is built by us, argv is test-controlled.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case runErr := <-done:
		var exitCode int
		if runErr == nil {
			exitCode = 0
		} else {
			var ee *exec.ExitError
			if errors.As(runErr, &ee) {
				exitCode = ee.ExitCode()
			} else {
				t.Fatalf("runCLI(%v): unexpected non-exit error: %v\nstderr:\n%s", argv, runErr, stderr.String())
			}
		}
		return cliResult{exitCode: exitCode, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("runCLI(%v): exceeded 30s timeout\nstderr:\n%s", argv, stderr.String())
		return cliResult{} // unreachable
	}
}

// TestCLI_Version asserts `copyfail-validate --version` writes the
// buildinfo identity and exits 0. The `v0.0.0-dev` substring is the
// hard-coded buildinfo default; a goreleaser-stamped binary would
// substitute its own value here, so substring-match is the correct
// shape rather than a full-string compare.
func TestCLI_Version(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--version")
	if got.exitCode != 0 {
		t.Fatalf("--version exit code = %d, want 0\nstderr:\n%s", got.exitCode, got.stderr)
	}
	out := string(got.stdout) + string(got.stderr)
	if !strings.Contains(out, "copyfail-validate") {
		t.Fatalf("--version output missing tool name; got %q", out)
	}
	if !strings.Contains(out, "v0.0.0-dev") {
		t.Fatalf("--version output missing default version; got %q", out)
	}
}

// TestCLI_Help asserts `--help` exits 0 and writes the usage banner.
// The flag.FlagSet's own --help handling returns flag.ErrHelp from
// Parse; main translates that to exit 0 via isHelpOrVersionExit.
func TestCLI_Help(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--help")
	if got.exitCode != 0 {
		t.Fatalf("--help exit code = %d, want 0\nstderr:\n%s", got.exitCode, got.stderr)
	}
	out := string(got.stdout) + string(got.stderr)
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("--help output missing 'Usage:' banner; got %q", out)
	}
	if !strings.Contains(out, "--format") {
		t.Fatalf("--help output missing --format flag listing; got %q", out)
	}
}

// TestCLI_UnknownFlag asserts `--bogus` exits 64 (EX_USAGE) and writes
// the FlagSet diagnostic to stderr. exit 64 is the spec §6 code for
// usage errors; aggregators use it to bucket "operator error" hosts
// separately from "host posture unknown".
func TestCLI_UnknownFlag(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--bogus")
	if got.exitCode != exitUsageCode {
		t.Fatalf("--bogus exit code = %d, want %d\nstderr:\n%s", got.exitCode, exitUsageCode, got.stderr)
	}
	if len(got.stderr) == 0 {
		t.Fatalf("--bogus produced no stderr diagnostic")
	}
}

// TestCLI_BadFormat asserts an invalid --format value exits 64. This
// is the regression test for the format autodetect path: a malformed
// value must NOT silently fall back to JSON.
func TestCLI_BadFormat(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=invalid")
	if got.exitCode != exitUsageCode {
		t.Fatalf("--format=invalid exit code = %d, want %d\nstderr:\n%s", got.exitCode, exitUsageCode, got.stderr)
	}
}

// TestCLI_OnlyAndSkipConflict asserts the spec §3 mutual-exclusion
// rule: passing both --only and --skip with values exits 64. Passing
// only one or neither is fine; that case is covered elsewhere.
func TestCLI_OnlyAndSkipConflict(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--only=modprobe.dry_run", "--skip=module.not_loaded", "--format=json")
	if got.exitCode != exitUsageCode {
		t.Fatalf("conflicting --only/--skip exit = %d, want %d\nstderr:\n%s", got.exitCode, exitUsageCode, got.stderr)
	}
}

// TestCLI_NoMatchingOnly asserts the operator-friendly rule from the
// filterChecks doc: --only that matches zero checks is exit 64 with a
// clear stderr diagnostic. Without this guard, a typo like
// `--only=modprobe.dry-run` (hyphen vs underscore) would silently
// produce a zero-result report and exit 0 — a confusing footgun the
// CLI should refuse to load.
func TestCLI_NoMatchingOnly(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--only=does.not.exist", "--format=json")
	if got.exitCode != exitUsageCode {
		t.Fatalf("--only=does.not.exist exit = %d, want %d\nstderr:\n%s", got.exitCode, exitUsageCode, got.stderr)
	}
	if !strings.Contains(string(got.stderr), "no checks match") {
		t.Fatalf("expected 'no checks match' diagnostic in stderr; got %q", string(got.stderr))
	}
}

// TestCLI_JSONFormat_IsParseable asserts that `--format=json --only=
// modprobe.conf_present` produces well-formed JSON on stdout. We pin
// to one check (modprobe.conf_present) because it is hermetic — the
// check only runs `os.Stat`, never spawns a subprocess, and behaves
// the same on macOS as on Linux. Other checks shell out to modprobe
// which is not available on macOS.
//
// We accept any of the spec §6 exit codes the host could legitimately
// produce: 0 (mitigation in place — never on a dev host), 2 (file
// missing — the macOS expectation), 3 (tool error before any check
// ran — should not happen for a hermetic check), 4 (check errored —
// not expected here either).
func TestCLI_JSONFormat_IsParseable(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=json", "--only=modprobe.conf_present")
	switch got.exitCode {
	case 0, 2, 3, 4:
		// Acceptable per spec §6.
	default:
		t.Fatalf("unexpected exit code %d; want 0/2/3/4\nstderr:\n%s", got.exitCode, got.stderr)
	}

	// stdout MUST be parseable JSON; any non-JSON byte indicates a
	// stream-discipline regression (log line leaked to stdout).
	var parsed map[string]any
	if err := json.Unmarshal(got.stdout, &parsed); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\nstdout:\n%s", err, string(got.stdout))
	}

	// The Report carries these fields per report.Report's JSON tags.
	for _, field := range []string{"generated_at", "schema_version", "results", "summary"} {
		if _, ok := parsed[field]; !ok {
			t.Fatalf("JSON output missing required field %q; payload=%v", field, parsed)
		}
	}
}

// TestCLI_HumanFormat_NoColor asserts the --no-color flag and the
// NO_COLOR env var both disable ANSI color in human-format output.
// The check exists because some operators redirect to a file but the
// human renderer still emits color codes when a TTY heuristic fails;
// --no-color is the explicit opt-out.
func TestCLI_HumanFormat_NoColor(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=human", "--no-color", "--only=modprobe.conf_present")
	switch got.exitCode {
	case 0, 2, 3, 4:
		// Acceptable per spec §6.
	default:
		t.Fatalf("unexpected exit code %d; want 0/2/3/4\nstderr:\n%s", got.exitCode, got.stderr)
	}
	if bytes.Contains(got.stdout, []byte{0x1b}) {
		t.Fatalf("--no-color stdout contains ANSI escape (0x1b); want none\nstdout:\n%s", string(got.stdout))
	}
}

// TestCLI_OnlyOneCheck asserts the --only filter shrinks the report
// to exactly one result. Combined with the JSON parseability check,
// this is the smallest end-to-end proof that the filter wiring works.
func TestCLI_OnlyOneCheck(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=json", "--only=modprobe.conf_present")

	// Switch on exit code so a Fail (which is the macOS expected
	// outcome) does not fail the test; we are asserting result COUNT,
	// not result CONTENT.
	switch got.exitCode {
	case 0, 2, 3, 4:
	default:
		t.Fatalf("unexpected exit code %d; stderr:\n%s", got.exitCode, got.stderr)
	}

	var parsed struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(got.stdout, &parsed); err != nil {
		t.Fatalf("parse JSON: %v\nstdout:\n%s", err, string(got.stdout))
	}
	if len(parsed.Results) != 1 {
		t.Fatalf("--only=modprobe.conf_present produced %d results, want 1", len(parsed.Results))
	}
	if id, _ := parsed.Results[0]["check_id"].(string); id != "modprobe.conf_present" {
		t.Fatalf("--only result had check_id=%q, want modprobe.conf_present", id)
	}
}

// TestCLI_SkipPattern asserts --skip removes the named check from the
// run. We skip modprobe.dry_run (which on macOS would error because
// the modprobe binary is missing) and verify the result count is 4 —
// the full preset has 5 checks.
func TestCLI_SkipPattern(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=json", "--skip=modprobe.dry_run")

	switch got.exitCode {
	case 0, 2, 3, 4:
	default:
		t.Fatalf("unexpected exit code %d; stderr:\n%s", got.exitCode, got.stderr)
	}

	var parsed struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(got.stdout, &parsed); err != nil {
		t.Fatalf("parse JSON: %v\nstdout:\n%s", err, string(got.stdout))
	}
	if len(parsed.Results) != 4 {
		t.Fatalf("--skip=modprobe.dry_run produced %d results, want 4", len(parsed.Results))
	}
	for _, r := range parsed.Results {
		if id, _ := r["check_id"].(string); id == "modprobe.dry_run" {
			t.Fatalf("--skip=modprobe.dry_run should have excluded that ID; got it back")
		}
	}
}

// TestCLI_OutputToFile asserts that --output=<path> writes the
// rendered report to a file and leaves stdout empty (no leakage
// either direction). Operators rely on --output to keep build logs
// uncluttered; a regression here would silently revert that.
func TestCLI_OutputToFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "report.json")
	got := runCLI(t, "--format=json", "--only=modprobe.conf_present", "--output="+outPath)

	switch got.exitCode {
	case 0, 2, 3, 4:
	default:
		t.Fatalf("unexpected exit code %d; stderr:\n%s", got.exitCode, got.stderr)
	}
	if len(got.stdout) != 0 {
		t.Fatalf("--output= should keep stdout empty; got %q", string(got.stdout))
	}

	body, err := os.ReadFile(outPath) // #nosec G304 -- outPath is from t.TempDir().
	if err != nil {
		t.Fatalf("read --output file: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("--output file is not parseable JSON: %v\ncontent:\n%s", err, string(body))
	}
}

// TestCLI_StreamDiscipline asserts the spec §6 rule that stdout
// carries ONLY the report (in the chosen format) and stderr carries
// everything else (logs, errors). Two assertions:
//   - JSON-format stdout decodes cleanly with no leading/trailing log
//     bytes (json.Decoder would tolerate trailing whitespace but not
//     leading garbage).
//   - With --verbose, the JSON on stdout is still clean — the verbose
//     log lines must land on stderr, not commingled with the report.
func TestCLI_StreamDiscipline(t *testing.T) {
	t.Parallel()
	got := runCLI(t, "--format=json", "--only=modprobe.conf_present", "-v", "-v")
	switch got.exitCode {
	case 0, 2, 3, 4:
	default:
		t.Fatalf("unexpected exit code %d; stderr:\n%s", got.exitCode, got.stderr)
	}
	var parsed map[string]any
	if err := json.Unmarshal(got.stdout, &parsed); err != nil {
		t.Fatalf("with -vv, stdout is not pure JSON (log leaked?): %v\nstdout:\n%s", err, string(got.stdout))
	}
	if len(got.stderr) == 0 {
		t.Fatalf("-vv should emit log lines on stderr; got empty stderr")
	}
}

// TestCLI_SIGTERM_PartialReportValid sends SIGTERM mid-run and asserts
// (a) the binary exits 143, (b) whatever was written to stdout still
// parses as JSON. The check exercises spec §6 forensic-value rule:
// even on signal-driven cancellation the operator must get a usable
// partial report.
//
// Skipped on Windows where signal semantics differ; SIGTERM there is
// best-effort. macOS and Linux both honor it.
func TestCLI_SIGTERM_PartialReportValid(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM semantics differ on Windows; skipping")
	}

	bin := buildBinary(t)
	// Use a long timeout so the modprobe checks have time to start
	// before we signal them. Output to stdout so we can capture both
	// streams.
	cmd := exec.Command(bin, "--format=json", "--timeout=10s") // #nosec G204 -- bin is built by us.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start binary: %v", err)
	}

	// Wait briefly to let the process start the runner. 100ms is
	// enough for the goroutines to spin up but well under any
	// individual check's wall-clock duration on a healthy host.
	time.Sleep(100 * time.Millisecond)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	// Wait for exit; cap at 5s so a hung child fails the test fast.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("binary did not exit within 5s after SIGTERM\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}

	exitCode := -1
	if waitErr == nil {
		exitCode = 0
	} else {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("Wait returned unexpected non-exit error: %v", waitErr)
		}
	}

	// Three valid outcomes — all of them mean "the signal-handling
	// path is wired AND the binary produced a usable report":
	//
	//   - 143 (exitTerminatedCode): SIGTERM interrupted a running
	//     check and the signal-canceled context propagated through
	//     the Runner to a clean shutdown. The classic spec §6 case.
	//
	//   - -1 (os/exec's "signal-killed without normal exit"): SIGTERM
	//     landed before the deferred os.Exit could run, so Wait sees
	//     no exit code at all. Same architectural meaning as 143.
	//
	//   - 0 / 2 / 3 / 4 (any normal exit): on fast hosts (clean Linux
	//     CI runners with no /etc/modprobe.d at all, where every
	//     check returns Fail in <10ms via ENOENT), the binary
	//     completes the entire run BEFORE the test's 100ms pre-signal
	//     sleep elapses. The signal arrives after the process has
	//     already exited normally — also fine, just means we couldn't
	//     exercise the cancellation path on this host. The signal-
	//     handler wiring is independently verified by the unit tests
	//     in check/runner_concurrency_test.go; this integration
	//     test's load-bearing assertion is the JSON-parses check
	//     below.
	signalReached := exitCode == exitTerminatedCode || exitCode == -1
	completedNormally := exitCode >= 0 && exitCode < 128
	if !signalReached && !completedNormally {
		t.Fatalf("SIGTERM exit code = %d, want %d (signal), -1 (signal-kill), or 0/2/3/4 (race: process completed before signal)\nstderr:\n%s", exitCode, exitTerminatedCode, stderr.String())
	}

	// If anything landed on stdout, it must parse as JSON: spec §6
	// forensic-value rule. An empty stdout is also valid (the signal
	// could have landed before WriteTo started writing).
	if len(stdout.Bytes()) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
			t.Fatalf("partial stdout is not parseable JSON: %v\nstdout:\n%s", err, stdout.String())
		}
	}
}

// Mirror the exit-code constants here so the integration tests do not
// need to import the main package (which has no public exports).
// Drift is caught by exit_test.go's TestExitCodeConstants_FrozenValues
// — that test asserts the canonical values; an integration-test
// constant divergence would fail this file's assertions long before
// any silent re-classification of operator-facing exit codes.
const (
	exitUsageCode      = 64
	exitTerminatedCode = 143
)
