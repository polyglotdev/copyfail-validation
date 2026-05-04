// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Command copyfail-validate is the CLI frontend for the copyfail-
// validation library. It wires preset/copyfail.AllWithOptions through
// check.Runner.Run, renders the resulting report.Report via the
// internal/render package (registered for all four formats by blank
// import below), and exits with the spec §6 codes the operator's
// fleet aggregator pivots on.
//
// Run with --help to see the full flag surface; the spec lives at
// docs/superpowers/specs/2026-05-04-copyfail-validation-design.md
// (canonical) and is summarized in the writeUsage helper.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
	"github.com/polyglotdev/copyfail-validation/internal/logging"
	_ "github.com/polyglotdev/copyfail-validation/internal/render" // register renderers — DO NOT REMOVE; see internal/render/init.go
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
	"github.com/polyglotdev/copyfail-validation/report"
)

// nowFunc is the time source for the generated-at timestamp. Tests
// override this to assert deterministic output without coupling to
// wall-clock time.
var nowFunc = func() time.Time { return time.Now().UTC() }

// noColorEnv is the spec-mandated env var name (NO_COLOR; see no-color.org)
// the render package consults to disable ANSI color in human output. The
// CLI sets it when --no-color is passed so the env-driven path is the
// single source of truth, both for explicit operator opt-out and for
// downstream tooling that already exports it.
const noColorEnv = "NO_COLOR"

// main is the CLI entry point. Returns nothing (the exit code is sent
// to os.Exit directly) so the test binary's TestMain can call run()
// with constructed arguments instead of having to mutate os.Args.
func main() {
	opts, err := parseFlags(os.Args[1:], os.Stderr)
	if err != nil {
		if isHelpOrVersionExit(err) {
			os.Exit(exitOK)
		}
		fmt.Fprintln(os.Stderr, "copyfail-validate:", err)
		os.Exit(exitUsage)
	}
	os.Exit(run(opts))
}

// run is the testable core of the CLI. It owns the signal handler, the
// hostinfo gather, the runner construction, the output open, the render
// call, and the final exit-code computation. Returns an int the caller
// (main, or a test using run() directly) hands to os.Exit.
//
// The function deliberately does NOT call os.Exit itself so test code
// can inspect the returned int without the test process dying.
func run(opts options) int {
	if opts.NoColor {
		// The render package reads NO_COLOR via os.Getenv; the safest
		// way to plumb the flag through without leaking a global is to
		// set the env var for our own process. The change is
		// process-local, not exported to children we spawn (we don't
		// spawn anything other than the allowlisted exec subprocesses,
		// which neither emit color nor inherit our os.Setenv mutation
		// in a way that affects their behavior).
		if err := os.Setenv(noColorEnv, "1"); err != nil {
			fmt.Fprintln(os.Stderr, "copyfail-validate: set NO_COLOR:", err)
			return exitToolError
		}
	}

	logger := logging.New(logging.Options{
		Verbosity: opts.Verbosity,
		Writer:    os.Stderr,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runner := exec.NewOSRunner()

	// Gather hostinfo before constructing checks. A failure here is a
	// tool-level error (exitToolError = 3): we cannot produce a
	// trustworthy report without the host context the renderer stamps
	// into Report.Host.
	host, hostErr := hostinfo.Gather(ctx, runner)
	if hostErr != nil {
		// Non-fatal in the spirit of the hostinfo contract: the
		// returned host is partially populated and still usable for
		// audit logs. Log the error and continue with whatever was
		// gathered. A FULLY empty host (no hostname, no kernel) is
		// rare and would surface in the rendered output.
		logger.Warn("hostinfo gather degraded",
			slog.String("err", hostErr.Error()))
	}

	checks := copyfail.AllWithOptions(copyfail.Options{
		Module:   opts.Module,
		ConfPath: opts.Conf,
		Runner:   runner,
	})

	filtered, filterErr := filterChecks(checks, opts.Only, opts.Skip)
	if filterErr != nil {
		fmt.Fprintln(os.Stderr, "copyfail-validate:", filterErr)
		return exitUsage
	}

	r := check.Runner{
		Concurrency: opts.Concurrency,
		Timeout:     opts.Timeout,
		Logger:      logger,
	}
	rep := r.Run(ctx, filtered)
	rep.SchemaVersion = report.SchemaVersionCurrent
	rep.Tool = buildinfo.Info()
	rep.Host = host
	rep.Generated = nowFunc()

	out, closer, openErr := openOutput(opts.Output)
	if openErr != nil {
		logger.Error("open output", slog.String("err", openErr.Error()))
		return exitToolError
	}
	defer closer()

	if _, writeErr := rep.WriteTo(out, opts.Format); writeErr != nil {
		logger.Error("render report",
			slog.String("err", writeErr.Error()),
			slog.String("format", string(opts.Format)))
		return exitToolError
	}

	// Signal-driven exit takes precedence over the Summary-driven exit
	// code. ctx.Err() is non-nil iff a signal landed (or some other
	// cancellation, but signal.NotifyContext is the only canceler we
	// install).
	if signalCode := signalExitCode(ctx); signalCode != 0 {
		return signalCode
	}

	return computeExit(rep)
}

// filterChecks applies the --only / --skip filters to checks and
// returns the resulting subset. The mutual-exclusion constraint was
// already enforced at flag-parse time, so at most one of only/skip is
// non-empty here.
//
// Returns an error when --only matches zero checks: an operator who
// types `--only=typo.check_id` deserves a loud "no checks match" rather
// than a silent zero-result report that exits 0.
func filterChecks(checks []check.Check, only, skip []string) ([]check.Check, error) {
	if len(only) > 0 {
		set := toSet(only)
		out := make([]check.Check, 0, len(checks))
		for _, c := range checks {
			if _, ok := set[c.ID()]; ok {
				out = append(out, c)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no checks match --only filter %v", only)
		}
		return out, nil
	}
	if len(skip) > 0 {
		set := toSet(skip)
		out := make([]check.Check, 0, len(checks))
		for _, c := range checks {
			if _, drop := set[c.ID()]; drop {
				continue
			}
			out = append(out, c)
		}
		return out, nil
	}
	return checks, nil
}

// toSet collects ids into a map for O(1) membership tests. Pure helper
// so filterChecks reads top-down without inline map construction.
func toSet(ids []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

// openOutput resolves the --output flag value into an io.Writer plus a
// closer the caller defers. The "-" sentinel returns os.Stdout with a
// no-op closer (closing stdout would break any subsequent fmt.Fprintln
// to it, including from the panic path).
//
// Errors are wrapped with the path so operators can distinguish "file
// permission denied at /var/log/cf.json" from "directory does not
// exist for /var/log/cf.json".
func openOutput(path string) (io.Writer, func(), error) {
	if path == stdoutSentinel {
		return os.Stdout, func() {}, nil
	}
	// #nosec G304 -- path is operator-controlled via --output, the
	// canonical use case for this flag. We rely on filesystem ACLs to
	// gate writes; the CLI does not have a privilege boundary to defend.
	// Mode 0o600 keeps reports operator-readable only by default; if
	// an operator wants group-readable output they can pre-create the
	// file or chmod it afterward.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// signalExitCode returns the spec §6 exit code matching the cancel
// reason on ctx, or 0 if the context was not canceled. Used by run to
// short-circuit the Summary-driven exit when a signal landed mid-run
// — operators want the CLI to honor the shell's `Ctrl+C` semantics
// (exit 130 for SIGINT, 143 for SIGTERM) regardless of the partial
// Report's pass/fail counts.
//
// Limitation: signal.NotifyContext does not record WHICH signal
// triggered the cancel, so we cannot distinguish SIGINT from SIGTERM
// post-hoc. The CLI defaults to exitTerminated (SIGTERM, 143) when the
// context is canceled and we cannot prove SIGINT, because SIGTERM is
// the more common fleet-orchestration signal (SSM, systemd, k8s); a
// SIGINT-only mis-classification would only surface to a developer at
// the terminal and matters less than a SIGTERM mis-classification in
// production.
func signalExitCode(ctx context.Context) int {
	if ctx.Err() == nil {
		return 0
	}
	if !errors.Is(ctx.Err(), context.Canceled) {
		// Some other cancellation (deadline exceeded etc.). Not a
		// signal exit; let the Summary-driven path handle it.
		return 0
	}
	return exitTerminated
}
