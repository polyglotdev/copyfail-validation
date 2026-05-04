// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// defaultPerCheckTimeout is the wall-clock cap applied to every check
// when the operator does not pass --timeout. 30 seconds matches the
// spec §3 default and the check.Runner default; we duplicate the
// constant rather than import it from check so a future divergence is
// caught by the lint rather than silently propagated.
const defaultPerCheckTimeout = 30 * time.Second

// stdoutSentinel is the --output value that means "write to stdout".
// Matches every other CLI in the ecosystem (`-` for stdin/stdout) so
// pipelines composing copyfail-validate with `jq`/`tee` work the way
// operators expect.
const stdoutSentinel = "-"

// Sentinel errors returned by parseFlags. Tests use errors.Is to assert
// which class of failure the flag layer surfaced; the wrapped messages
// are operator-facing and may evolve without breaking the test surface.
var (
	// errHelpOrVersion is returned when the operator passed --help or
	// --version. main treats it as a clean exit (exitOK), not a usage
	// error. The error itself carries the help/version output via the
	// io.Writer the parser was constructed with.
	errHelpOrVersion = errors.New("flags: help or version requested")

	// errFlagConflict is returned when --only and --skip both carry
	// values; they are mutually exclusive per spec §3 (selecting and
	// excluding the same set of checks at once is meaningless).
	errFlagConflict = errors.New("flags: --only and --skip are mutually exclusive")

	// errFlagParse is returned when the underlying flag.FlagSet rejects
	// a value (unknown flag, malformed duration, non-integer
	// concurrency). The wrapped error carries the FlagSet message.
	errFlagParse = errors.New("flags: parse error")

	// errEmptyFilter is returned when the operator passed --only or
	// --skip with an empty / whitespace-only value; this is almost
	// always a shell mishap (e.g., `--only=$EMPTY`) and we surface it
	// loudly rather than silently treating it as "no filter".
	errEmptyFilter = errors.New("flags: --only / --skip value is empty")
)

// options carries every CLI-flag-derived value through the run path.
// Field declaration order favors govet fieldalignment: pointer/slice/
// string headers first (16 bytes each on 64-bit), then ints (8 bytes),
// then the bool tail.
type options struct {
	// Format is the output format selected via --format. Validated by
	// report.ParseFormat at flag-parse time so an invalid value is a
	// usage error rather than a render-time error.
	Format report.Format

	// Output is the path the rendered report writes to. The literal
	// "-" means os.Stdout; any other value is an absolute or relative
	// path the CLI opens with O_CREATE | O_WRONLY | O_TRUNC.
	Output string

	// Module overrides preset/copyfail.DefaultModule. Lets operators
	// validate other AF_ALG-family modules (algif_skcipher, algif_hash,
	// algif_rng) without rebuilding the binary.
	Module string

	// Conf overrides preset/copyfail.DefaultConfPath. The path is
	// passed through to the conf-present and conf-correct checks.
	Conf string

	// Only is the --only filter: a list of check IDs that, when
	// non-empty, restricts the run to exactly those checks. Mutually
	// exclusive with Skip.
	Only []string

	// Skip is the --skip filter: a list of check IDs that, when
	// non-empty, excludes those checks from the run. Mutually
	// exclusive with Only.
	Skip []string

	// Timeout is the per-check wall-clock cap. Threads through to
	// check.Runner.Timeout.
	Timeout time.Duration

	// Concurrency is the maximum number of checks running in parallel.
	// Zero means runtime.NumCPU() (check.Runner default).
	Concurrency int

	// Verbosity is the cumulative -v count. 0 = warn, 1 = info, 2 =
	// debug; threads through to logging.Options.Verbosity.
	Verbosity int

	// NoColor disables ANSI color output in human-format render.
	// Honored by the render package via the EnvNoColor env var the
	// CLI sets when this is true.
	NoColor bool
}

// parseFlags parses argv (everything after os.Args[0]) and returns the
// resulting options or an error. errOut is where help / version /
// usage messages land (production: os.Stderr; tests: a *bytes.Buffer).
//
// Errors:
//   - errHelpOrVersion: --help or --version was requested. Caller
//     should exit 0.
//   - errFlagConflict: --only and --skip both carried values.
//   - errFlagParse: the underlying flag.FlagSet rejected a value, or
//     --format carried an unknown value (wraps report.ErrUnknownFormat).
//   - errEmptyFilter: --only or --skip carried an empty value.
//
// Environment variables (lowest precedence — flags always win):
//   - COPYFAIL_FORMAT   (--format)
//   - COPYFAIL_TIMEOUT  (--timeout, parsed via time.ParseDuration)
//   - COPYFAIL_MODULE   (--module)
//   - COPYFAIL_CONF     (--conf)
func parseFlags(argv []string, errOut io.Writer) (options, error) {
	defaults := readEnvDefaults()

	fs := flag.NewFlagSet("copyfail-validate", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { writeUsage(errOut) }

	formatStr := fs.String("format", defaults.formatStr, "Output format: human|json|sarif|prometheus")
	output := fs.String("output", stdoutSentinel, "Output path; \"-\" for stdout")
	timeout := fs.Duration("timeout", defaults.timeout, "Per-check timeout")
	concurrency := fs.Int("concurrency", 0, "Max parallel checks (0 = NumCPU)")
	module := fs.String("module", defaults.module, "Override module name to validate")
	conf := fs.String("conf", defaults.conf, "Override modprobe.d path")
	skipCSV := fs.String("skip", "", "Comma-separated check IDs to skip")
	onlyCSV := fs.String("only", "", "Comma-separated check IDs to run exclusively")
	noColor := fs.Bool("no-color", false, "Disable ANSI colors (also honored: NO_COLOR env)")
	versionFlag := fs.Bool("version", false, "Print version and exit")

	verbosity := new(verbosityCount)
	fs.Var(verbosity, "v", "Increase logging verbosity (-v info, -vv debug)")
	fs.Var(verbosity, "verbose", "Increase logging verbosity (alias of -v)")

	if err := fs.Parse(argv); err != nil {
		// The FlagSet has already written a diagnostic to errOut via
		// Usage; we wrap so callers can errors.Is on the sentinel.
		return options{}, fmt.Errorf("%w: %w", errFlagParse, err)
	}

	if *versionFlag {
		writeVersion(errOut)
		return options{}, errHelpOrVersion
	}

	// Default for --format: if no flag and no env var, pick "human" on
	// a TTY else "json". This is the spec §3 behavior; operators get a
	// readable report when running interactively, machine-readable
	// output when piped or redirected.
	if *formatStr == "" {
		*formatStr = autoDetectFormat()
	}

	format, err := report.ParseFormat(*formatStr)
	if err != nil {
		return options{}, fmt.Errorf("%w: %w", errFlagParse, err)
	}

	only, err := parseCSVFilter(*onlyCSV, "only")
	if err != nil {
		return options{}, err
	}
	skip, err := parseCSVFilter(*skipCSV, "skip")
	if err != nil {
		return options{}, err
	}
	if len(only) > 0 && len(skip) > 0 {
		return options{}, errFlagConflict
	}

	return options{
		Format:      format,
		Output:      *output,
		Timeout:     *timeout,
		Concurrency: *concurrency,
		Module:      *module,
		Conf:        *conf,
		Only:        only,
		Skip:        skip,
		NoColor:     *noColor,
		Verbosity:   int(*verbosity),
	}, nil
}

// envDefaultValues bundles the four COPYFAIL_* environment variables
// into a single struct so the flag declarations above stay readable.
// Flags always override env; env always overrides hard-coded defaults.
type envDefaultValues struct {
	formatStr string
	module    string
	conf      string
	timeout   time.Duration
}

// readEnvDefaults reads the four COPYFAIL_* environment variables and
// returns a struct populated with whichever ones were set. Unset /
// empty vars fall through to the hard-coded defaults so flag
// declarations always see a sensible non-empty value.
func readEnvDefaults() envDefaultValues {
	out := envDefaultValues{
		formatStr: "", // empty triggers TTY autodetect in parseFlags
		module:    copyfail.DefaultModule,
		conf:      copyfail.DefaultConfPath,
		timeout:   defaultPerCheckTimeout,
	}
	if v := os.Getenv("COPYFAIL_FORMAT"); v != "" {
		out.formatStr = v
	}
	if v := os.Getenv("COPYFAIL_MODULE"); v != "" {
		out.module = v
	}
	if v := os.Getenv("COPYFAIL_CONF"); v != "" {
		out.conf = v
	}
	if v := os.Getenv("COPYFAIL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			out.timeout = d
		}
	}
	return out
}

// verbosityCount implements flag.Value as a counting flag: every -v on
// the command line increments the int. flag.Var's bool semantics would
// only set the value once, so we drop in our own type that ignores the
// "true"/"false" passed by the FlagSet (it always passes "true" for a
// bool-shaped flag with no value) and just bumps the counter.
type verbosityCount int

// String returns the current count as a decimal. The flag.Value
// interface requires this; flag.PrintDefaults reads it for the help
// line so a non-empty value is harmless.
func (v *verbosityCount) String() string {
	if v == nil {
		return "0"
	}
	return strconv.Itoa(int(*v))
}

// Set is called by the flag package once per occurrence of -v. We
// honor an explicit integer value (`-v=2`) but also accept the bare
// flag (`-v`) by treating the FlagSet-supplied "true" as "+1".
func (v *verbosityCount) Set(s string) error {
	switch strings.ToLower(s) {
	case "true":
		*v++
		return nil
	case "false":
		// Operator explicitly disabled verbosity; reset to zero.
		*v = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("verbosity: parse %q: %w", s, err)
	}
	*v = verbosityCount(n)
	return nil
}

// IsBoolFlag tells the flag package this is a counting bool — it can
// be passed without a value. The package's own boolFlag interface has
// this exact name; satisfying it makes `-v -v -v` work without each
// occurrence demanding `=true`.
func (v *verbosityCount) IsBoolFlag() bool { return true }

// parseCSVFilter splits s on commas and returns the trimmed, non-empty
// items. An s that is empty (no flag passed) returns nil; an s that is
// non-empty but contains only whitespace / empty fragments returns
// errEmptyFilter wrapped with the field name so the operator can tell
// --only from --skip in the diagnostic.
func parseCSVFilter(s, field string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: --%s", errEmptyFilter, field)
	}
	return out, nil
}

// autoDetectFormat returns "human" when stdout is connected to a TTY,
// else "json". Detection uses os.ModeCharDevice on the os.Stdout fd —
// the same approach the internal/render package's TTY detection uses
// (kept duplicated rather than importing the internal helper because
// the internal package is, by definition, internal). No external
// dependency on golang.org/x/term.
func autoDetectFormat() string {
	info, err := os.Stdout.Stat()
	if err != nil {
		return string(report.FormatJSON)
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return string(report.FormatHuman)
	}
	return string(report.FormatJSON)
}

// writeUsage prints the manpage-shaped help text to w. The text mirrors
// the spec §3 flag table; updates to either should land in lockstep.
//
// Write errors on the help-text path are intentionally swallowed: the
// caller is os.Stderr in production (a closed-stderr scenario means
// the process is in an unrecoverable state already) and a *bytes.Buffer
// in tests (which never fails Write).
func writeUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `copyfail-validate - validate AF_ALG-family kernel-crypto mitigations

Usage:
  copyfail-validate [flags]

Flags:
  --format string         Output format: human|json|sarif|prometheus
                          (default "human" on TTY, "json" otherwise)
  --output string         Output path; "-" for stdout (default "-")
  --timeout duration      Per-check timeout (default 30s)
  --concurrency int       Max parallel checks (default NumCPU)
  --module string         Override module name to validate
                          (default "algif_aead")
  --conf string           Override modprobe.d path
                          (default "/etc/modprobe.d/disable-algif-aead.conf")
  --skip strings          Comma-separated check IDs to skip
  --only strings          Comma-separated check IDs to run exclusively
  --no-color              Disable ANSI colors (also honored: NO_COLOR env)
  -v, --verbose           Increase logging verbosity (-v info, -vv debug)
  --version               Print version and exit
  -h, --help              Print this help and exit

Environment (lowest precedence):
  COPYFAIL_FORMAT, COPYFAIL_TIMEOUT, COPYFAIL_MODULE, COPYFAIL_CONF

Exit codes (frozen at v1.0.0):
  0    all required checks passed
  2    >=1 required check failed (mitigation gap)
  3    tool-level error before any check ran
  4    >=1 required check errored (could not validate)
  64   usage error (bad flag, conflicting --only/--skip)
  130  interrupted by SIGINT
  143  terminated by SIGTERM
`)
}

// isHelpOrVersionExit reports whether err is the sentinel parseFlags
// returns when --help or --version was requested. Centralized so main
// does not have to know about the unwrapping rules.
func isHelpOrVersionExit(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errHelpOrVersion) {
		return true
	}
	// flag.ErrHelp is what flag.FlagSet returns from Parse when the
	// user passed -h or --help. We wrap it via errFlagParse, so an
	// errors.Is check picks it up here.
	return errors.Is(err, flag.ErrHelp)
}

// writeVersion prints the buildinfo identity to w in the canonical
// `name version (commit X, built Y)` shape. Operators paste this into
// audit logs; matching the format that goreleaser stamps via -ldflags
// keeps `--version` output stable across the source-build /
// release-build divide.
//
// Write errors are swallowed for the same reason writeUsage swallows
// them — the version output must succeed-or-fail-silently rather than
// surface a wrapped Fprintln error to a caller already heading to
// os.Exit(0).
func writeVersion(w io.Writer) {
	info := buildinfo.Info()
	_, _ = fmt.Fprintf(w, "%s %s (commit %s, built %s)\n",
		info.Name, info.Version, info.Commit, info.BuildDate)
}
