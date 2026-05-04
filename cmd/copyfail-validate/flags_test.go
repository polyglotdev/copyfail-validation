// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestParseFlags_HappyPath_DefaultsAndOverrides covers the
// flag-parsing happy path with a parameterized table:
//   - the no-flag case (every option falls through to its default)
//   - one case per flag with a non-default value, asserting only the
//     field that flag controls (other fields stay at their default)
//   - the --no-color toggle (asserts NoColor stays false unset, true set)
//   - --module + --conf + --timeout (operator-tuned production case)
//
// Sentinel-error cases live in TestParseFlags_ErrorPaths so the happy-
// path table stays focused on the field-level wiring.
func TestParseFlags_HappyPath_DefaultsAndOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		argv []string
		want options
	}{
		{
			name: "no flags applies all defaults",
			argv: []string{},
			want: options{
				// Format default depends on TTY autodetect; in `go
				// test` os.Stdout is a pipe so the autodetect picks
				// FormatJSON. We assert that exactly.
				Format:      report.FormatJSON,
				Output:      stdoutSentinel,
				Timeout:     defaultPerCheckTimeout,
				Concurrency: 0,
				Module:      copyfail.DefaultModule,
				Conf:        copyfail.DefaultConfPath,
			},
		},
		{
			name: "explicit --format=human overrides autodetect",
			argv: []string{"--format=human"},
			want: options{
				Format:  report.FormatHuman,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "explicit --format=sarif",
			argv: []string{"--format=sarif"},
			want: options{
				Format:  report.FormatSARIF,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "explicit --format=prometheus",
			argv: []string{"--format=prometheus"},
			want: options{
				Format:  report.FormatPrometheus,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "--output=/tmp/report.json",
			argv: []string{"--output=/tmp/report.json"},
			want: options{
				Format:  report.FormatJSON,
				Output:  "/tmp/report.json",
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "--timeout=5s overrides default",
			argv: []string{"--timeout=5s"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: 5 * time.Second,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "--concurrency=4",
			argv: []string{"--concurrency=4"},
			want: options{
				Format:      report.FormatJSON,
				Output:      stdoutSentinel,
				Timeout:     defaultPerCheckTimeout,
				Concurrency: 4,
				Module:      copyfail.DefaultModule,
				Conf:        copyfail.DefaultConfPath,
			},
		},
		{
			name: "--module=algif_skcipher overrides default",
			argv: []string{"--module=algif_skcipher"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  "algif_skcipher",
				Conf:    copyfail.DefaultConfPath,
			},
		},
		{
			name: "--conf=/etc/modprobe.d/custom.conf",
			argv: []string{"--conf=/etc/modprobe.d/custom.conf"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    "/etc/modprobe.d/custom.conf",
			},
		},
		{
			name: "--no-color toggles NoColor",
			argv: []string{"--no-color"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
				NoColor: true,
			},
		},
		{
			name: "--only=modprobe.dry_run sets Only",
			argv: []string{"--only=modprobe.dry_run"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
				Only:    []string{"modprobe.dry_run"},
			},
		},
		{
			name: "--skip=modprobe.dry_run,module.not_loaded sets Skip",
			argv: []string{"--skip=modprobe.dry_run,module.not_loaded"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
				Skip:    []string{"modprobe.dry_run", "module.not_loaded"},
			},
		},
		{
			name: "single -v sets Verbosity=1",
			argv: []string{"-v"},
			want: options{
				Format:    report.FormatJSON,
				Output:    stdoutSentinel,
				Timeout:   defaultPerCheckTimeout,
				Module:    copyfail.DefaultModule,
				Conf:      copyfail.DefaultConfPath,
				Verbosity: 1,
			},
		},
		{
			name: "two -v flags sets Verbosity=2",
			argv: []string{"-v", "-v"},
			want: options{
				Format:    report.FormatJSON,
				Output:    stdoutSentinel,
				Timeout:   defaultPerCheckTimeout,
				Module:    copyfail.DefaultModule,
				Conf:      copyfail.DefaultConfPath,
				Verbosity: 2,
			},
		},
		{
			name: "--verbose alias bumps Verbosity",
			argv: []string{"--verbose"},
			want: options{
				Format:    report.FormatJSON,
				Output:    stdoutSentinel,
				Timeout:   defaultPerCheckTimeout,
				Module:    copyfail.DefaultModule,
				Conf:      copyfail.DefaultConfPath,
				Verbosity: 1,
			},
		},
		{
			name: "operator-tuned production combo: format/timeout/module/conf",
			argv: []string{
				"--format=sarif",
				"--timeout=10s",
				"--module=algif_aead",
				"--conf=/etc/modprobe.d/disable-algif-aead.conf",
			},
			want: options{
				Format:  report.FormatSARIF,
				Output:  stdoutSentinel,
				Timeout: 10 * time.Second,
				Module:  "algif_aead",
				Conf:    "/etc/modprobe.d/disable-algif-aead.conf",
			},
		},
		{
			name: "filter with whitespace and trailing comma is normalized",
			argv: []string{"--only= modprobe.dry_run , module.not_loaded ,"},
			want: options{
				Format:  report.FormatJSON,
				Output:  stdoutSentinel,
				Timeout: defaultPerCheckTimeout,
				Module:  copyfail.DefaultModule,
				Conf:    copyfail.DefaultConfPath,
				Only:    []string{"modprobe.dry_run", "module.not_loaded"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			// Each subtest gets its own buffer so a parallel run does
			// not race on the writer; the FlagSet writes nothing on a
			// happy-path parse but assertion failures may surface
			// noise we want to inspect per-test.
			var buf bytes.Buffer
			got, err := parseFlags(tc.argv, &buf)
			if err != nil {
				subT.Fatalf("parseFlags(%v) returned unexpected error: %v\nstderr:\n%s", tc.argv, err, buf.String())
			}
			if !optionsEqual(got, tc.want) {
				subT.Fatalf("parseFlags(%v):\ngot:  %+v\nwant: %+v", tc.argv, got, tc.want)
			}
		})
	}
}

// TestParseFlags_ErrorPaths exhaustively covers the sentinel-returning
// paths: bad format, conflicting --only/--skip, empty-after-trim
// filters, and the underlying flag-parser failures (unknown flag, bad
// duration). Each case asserts the exact errors.Is match so a future
// renaming of the wrapped messages doesn't silently re-classify a
// failure mode.
func TestParseFlags_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantSent   error
		name       string
		wantStderr string
		argv       []string
	}{
		{
			name:     "unknown --format=invalid wraps errFlagParse",
			argv:     []string{"--format=invalid"},
			wantSent: errFlagParse,
		},
		{
			name:     "conflicting --only and --skip returns errFlagConflict",
			argv:     []string{"--only=modprobe.dry_run", "--skip=module.not_loaded"},
			wantSent: errFlagConflict,
		},
		{
			name:     "empty-after-trim --only value is errEmptyFilter",
			argv:     []string{"--only= , , "},
			wantSent: errEmptyFilter,
		},
		{
			name:     "empty-after-trim --skip value is errEmptyFilter",
			argv:     []string{"--skip=,"},
			wantSent: errEmptyFilter,
		},
		{
			name:     "unknown --bogus flag wraps errFlagParse",
			argv:     []string{"--bogus"},
			wantSent: errFlagParse,
		},
		{
			name:     "malformed --timeout wraps errFlagParse",
			argv:     []string{"--timeout=not-a-duration"},
			wantSent: errFlagParse,
		},
		{
			name:     "malformed --concurrency wraps errFlagParse",
			argv:     []string{"--concurrency=not-an-int"},
			wantSent: errFlagParse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			var buf bytes.Buffer
			_, err := parseFlags(tc.argv, &buf)
			if err == nil {
				subT.Fatalf("parseFlags(%v) returned nil error, want %v", tc.argv, tc.wantSent)
			}
			if !errors.Is(err, tc.wantSent) {
				subT.Fatalf("parseFlags(%v) error %v, want errors.Is(_, %v)",
					tc.argv, err, tc.wantSent)
			}
		})
	}
}

// TestParseFlags_VersionFlag asserts --version returns the
// errHelpOrVersion sentinel and writes the buildinfo identity to the
// errOut writer. main reads the sentinel via isHelpOrVersionExit and
// exits 0 cleanly — so a regression here would silently turn
// `copyfail-validate --version` into a usage error (exit 64).
func TestParseFlags_VersionFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_, err := parseFlags([]string{"--version"}, &buf)
	if !errors.Is(err, errHelpOrVersion) {
		t.Fatalf("parseFlags(--version) error %v, want errHelpOrVersion", err)
	}
	if !isHelpOrVersionExit(err) {
		t.Fatalf("isHelpOrVersionExit(%v) = false, want true", err)
	}
	out := buf.String()
	if !strings.Contains(out, "copyfail-validate") {
		t.Fatalf("--version output does not contain tool name: %q", out)
	}
	if !strings.Contains(out, "v0.0.0-dev") {
		t.Fatalf("--version output does not contain default version: %q", out)
	}
}

// TestParseFlags_HelpFlag asserts the underlying flag.ErrHelp surfaces
// via the same isHelpOrVersionExit check the version flag uses, so
// main exits 0 for `--help` even though the FlagSet returned a wrapped
// flag.ErrHelp rather than our own sentinel.
func TestParseFlags_HelpFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_, err := parseFlags([]string{"--help"}, &buf)
	if err == nil {
		t.Fatalf("parseFlags(--help) returned nil error, want a sentinel")
	}
	if !isHelpOrVersionExit(err) {
		t.Fatalf("isHelpOrVersionExit(%v) = false, want true", err)
	}
}

// TestParseFlags_EnvFallbackThenFlagWins asserts the precedence rule
// from the parseFlags godoc: a COPYFAIL_* env var fills a default when
// the flag is unset, but loses to an explicit flag value. The test
// uses t.Setenv (auto-restored on cleanup) so the host's environment
// is not mutated past the test boundary.
//
// Neither this parent test nor any subtest may call t.Parallel():
// t.Setenv panics if invoked from a parallel test, and we run a small
// matrix of env-var permutations sequentially.
func TestParseFlags_EnvFallbackThenFlagWins(t *testing.T) {

	tests := []struct {
		name        string
		envFormat   string
		envModule   string
		envConf     string
		envTimeout  string
		wantFormat  report.Format
		wantModule  string
		wantConf    string
		argv        []string
		wantTimeout time.Duration
	}{
		{
			name:        "env supplies COPYFAIL_FORMAT when flag unset",
			envFormat:   "sarif",
			argv:        []string{},
			wantFormat:  report.FormatSARIF,
			wantModule:  copyfail.DefaultModule,
			wantConf:    copyfail.DefaultConfPath,
			wantTimeout: defaultPerCheckTimeout,
		},
		{
			name:        "flag overrides COPYFAIL_FORMAT when both set",
			envFormat:   "sarif",
			argv:        []string{"--format=json"},
			wantFormat:  report.FormatJSON,
			wantModule:  copyfail.DefaultModule,
			wantConf:    copyfail.DefaultConfPath,
			wantTimeout: defaultPerCheckTimeout,
		},
		{
			name:        "env supplies COPYFAIL_MODULE",
			envModule:   "algif_skcipher",
			argv:        []string{},
			wantFormat:  report.FormatJSON,
			wantModule:  "algif_skcipher",
			wantConf:    copyfail.DefaultConfPath,
			wantTimeout: defaultPerCheckTimeout,
		},
		{
			name:        "env supplies COPYFAIL_CONF",
			envConf:     "/etc/modprobe.d/test.conf",
			argv:        []string{},
			wantFormat:  report.FormatJSON,
			wantModule:  copyfail.DefaultModule,
			wantConf:    "/etc/modprobe.d/test.conf",
			wantTimeout: defaultPerCheckTimeout,
		},
		{
			name:        "env supplies COPYFAIL_TIMEOUT",
			envTimeout:  "15s",
			argv:        []string{},
			wantFormat:  report.FormatJSON,
			wantModule:  copyfail.DefaultModule,
			wantConf:    copyfail.DefaultConfPath,
			wantTimeout: 15 * time.Second,
		},
		{
			name:        "flag overrides COPYFAIL_TIMEOUT",
			envTimeout:  "15s",
			argv:        []string{"--timeout=2s"},
			wantFormat:  report.FormatJSON,
			wantModule:  copyfail.DefaultModule,
			wantConf:    copyfail.DefaultConfPath,
			wantTimeout: 2 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			// No subT.Parallel(): t.Setenv is incompatible with
			// parallel subtests sharing the parent process's env.
			subT.Setenv("COPYFAIL_FORMAT", tc.envFormat)
			subT.Setenv("COPYFAIL_MODULE", tc.envModule)
			subT.Setenv("COPYFAIL_CONF", tc.envConf)
			subT.Setenv("COPYFAIL_TIMEOUT", tc.envTimeout)

			var buf bytes.Buffer
			got, err := parseFlags(tc.argv, &buf)
			if err != nil {
				subT.Fatalf("parseFlags(%v) returned unexpected error: %v", tc.argv, err)
			}
			if got.Format != tc.wantFormat {
				subT.Fatalf("Format = %q, want %q", got.Format, tc.wantFormat)
			}
			if got.Module != tc.wantModule {
				subT.Fatalf("Module = %q, want %q", got.Module, tc.wantModule)
			}
			if got.Conf != tc.wantConf {
				subT.Fatalf("Conf = %q, want %q", got.Conf, tc.wantConf)
			}
			if got.Timeout != tc.wantTimeout {
				subT.Fatalf("Timeout = %v, want %v", got.Timeout, tc.wantTimeout)
			}
		})
	}
}

// TestVerbosityCount_FlagValueSemantics asserts the counting flag's
// behavior in isolation: it satisfies the bool-flag interface so `-v`
// works without `=`, increments per occurrence, and accepts an explicit
// integer (`--verbose=3`) as a one-shot setter rather than an
// increment.
func TestVerbosityCount_FlagValueSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		argv []string
		want int
	}{
		{name: "no -v flag yields zero", argv: []string{}, want: 0},
		{name: "single -v yields one", argv: []string{"-v"}, want: 1},
		{name: "double -v yields two", argv: []string{"-v", "-v"}, want: 2},
		{name: "triple -v yields three", argv: []string{"-v", "-v", "-v"}, want: 3},
		{name: "explicit -v=2 sets two", argv: []string{"-v=2"}, want: 2},
		{name: "explicit --verbose=5 sets five", argv: []string{"--verbose=5"}, want: 5},
		{name: "explicit --verbose=false resets to zero", argv: []string{"-v", "--verbose=false"}, want: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			var buf bytes.Buffer
			got, err := parseFlags(tc.argv, &buf)
			if err != nil {
				subT.Fatalf("parseFlags(%v) returned error: %v", tc.argv, err)
			}
			if got.Verbosity != tc.want {
				subT.Fatalf("Verbosity = %d, want %d", got.Verbosity, tc.want)
			}
		})
	}
}

// optionsEqual compares two options structs for the field set the
// happy-path table cares about. Direct == on the struct would also
// require slice equality, which Go does not provide for slices; this
// helper centralizes the slice comparison.
func optionsEqual(a, b options) bool {
	if a.Format != b.Format {
		return false
	}
	if a.Output != b.Output {
		return false
	}
	if a.Timeout != b.Timeout {
		return false
	}
	if a.Concurrency != b.Concurrency {
		return false
	}
	if a.Module != b.Module {
		return false
	}
	if a.Conf != b.Conf {
		return false
	}
	if a.NoColor != b.NoColor {
		return false
	}
	if a.Verbosity != b.Verbosity {
		return false
	}
	return stringSliceEqual(a.Only, b.Only) && stringSliceEqual(a.Skip, b.Skip)
}

// stringSliceEqual reports whether a and b carry the same elements in
// the same order. A nil slice and a length-zero non-nil slice are
// treated as equal — both encode "no filter" semantics for the caller.
func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
