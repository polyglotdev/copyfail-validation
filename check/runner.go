// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/polyglotdev/copyfail-validation/report"
)

// defaultTimeout is the per-check wall-clock limit applied when a
// caller leaves Runner.Timeout zero. 30 seconds matches the spec
// default (§4 CLI flags: --timeout 30s) and gives even an upstream-
// slow network probe (e.g., a `dig`-based DNS check) plenty of
// headroom while still bounding pathological hangs.
const defaultTimeout = 30 * time.Second

// stackBufBytes is the size of the buffer passed to runtime.Stack on
// panic recovery. 64 KiB covers ~700 frames at typical Go stack-frame
// densities, which is more than enough for any check call chain we
// would ever ship and still small enough that the buffer is allocated
// from the goroutine's existing stack rather than the heap.
const stackBufBytes = 64 << 10

// Runner executes a slice of Checks and assembles a report.Report.
// The zero Runner is valid and uses sensible defaults
// (Concurrency=runtime.NumCPU(), Timeout=30s, Logger=nil).
//
// # Concurrency model
//
// The Runner dispatches work in input order from a single goroutine
// that blocks on a bounded-capacity semaphore. The dispatcher
// acquires a token, then spawns the worker; the worker releases the
// token when it finishes. This guarantees:
//
//   - At most Runner.Concurrency workers are running at once.
//   - Workers START in input order. Setting Concurrency=1 makes the
//     Runner deterministically sequential — useful for debugging or
//     when checks share a rate-limited resource.
//
// # Order guarantee
//
// Runner.Run returns Report.Results in the SAME order as the input
// checks slice, regardless of which check finished first. Results are
// written into a pre-allocated slice indexed by position so no sort
// or map traversal is involved. This is what makes `diff` between two
// days of output highlight real changes rather than reorderings.
//
// # Panic recovery
//
// If a check's Run or Applicable method panics, the Runner catches
// the panic, records a StateError result whose Err field carries
// "panic: <recovered value>", and (if Logger is non-nil) logs an
// error-level line with the recovered value and a runtime.Stack
// trace. The binary never crashes mid-run because of one buggy
// check.
//
// # Cancellation semantics
//
// Canceling the parent ctx abandons the run and returns the
// assembled-so-far Report. The Runner waits for in-flight checks
// using a select over both ctx.Done() and the workers' completion
// signal — when ctx fires, the Runner stops waiting and fills any
// not-yet-completed result slots with a StateError carrying the
// parent's context.Err. Once Run has returned, leaked workers
// (one per misbehaving, ctx-ignoring check) may still be running
// in the background; they no longer have permission to touch the
// returned Report's Results slice (a "frozen" flag enforces this
// under the same mutex that guards normal writes), so the caller
// sees a stable snapshot. A security tool must always produce a
// report.
type Runner struct {
	// Logger receives one info-level log line per check completion
	// ("check_id=… state=… duration_ms=…") plus error-level lines on
	// panic recovery and start/end summary lines. Nil disables
	// structured logging — useful for tests and library consumers
	// who do their own observability.
	Logger *slog.Logger

	// Timeout is the per-check wall-clock limit. Zero (the default)
	// uses defaultTimeout (30 seconds). A check that exceeds Timeout
	// has its own context canceled; a well-behaved check observes
	// ctx.Done() and returns StateError carrying ctx.Err. A buggy
	// check that ignores ctx will hold its worker slot until it
	// returns of its own accord — see the cancellation-semantics
	// section above for how the Runner protects the overall run.
	Timeout time.Duration

	// Concurrency is the maximum number of Checks running in
	// parallel. Zero (the default) uses runtime.NumCPU(). Setting
	// Concurrency to 1 makes the Runner deterministically sequential.
	Concurrency int
}

// runState bundles the per-Run shared state passed between the
// dispatcher and worker goroutines. Bundling avoids passing eight
// arguments to runOne and keeps the related fields adjacent in
// reviewer scans.
type runState struct {
	results   []report.Result
	completed []bool
	mu        sync.Mutex
	frozen    bool
}

// Run executes the given checks and returns the assembled Report.
//
// The returned Report has these fields populated:
//
//   - Generated   — time.Now().UTC() captured at Run start.
//   - Results     — len(checks) entries, in input order.
//   - Summary     — report.NewSummary(Results).
//
// SchemaVersion, Tool, and Host are deliberately left as zero values:
// those describe the calling binary and the host environment and are
// the CLI's responsibility to populate.
//
// Canceling ctx mid-run: in-flight checks see their per-check ctx
// canceled (via context.WithTimeout chained from the parent) and
// SHOULD return promptly with a StateError carrying ctx.Err. The
// Runner itself stops waiting once ctx is done — see the Runner
// godoc's cancellation-semantics section.
func (r *Runner) Run(ctx context.Context, checks []Check) report.Report {
	concurrency := r.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	rep := report.Report{
		Generated: time.Now().UTC(),
		Results:   make([]report.Result, len(checks)),
	}

	if len(checks) == 0 {
		rep.Summary = report.NewSummary(rep.Results)
		return rep
	}

	r.logf(ctx, slog.LevelInfo, "runner starting",
		slog.Int("total_checks", len(checks)),
		slog.Int("concurrency", concurrency),
		slog.Int64("timeout_ms", timeout.Milliseconds()),
	)

	state := &runState{
		results:   rep.Results,
		completed: make([]bool, len(checks)),
	}

	// sem is the bounded-parallel semaphore. Sized to concurrency so
	// at most that many workers may hold a token simultaneously. The
	// dispatcher acquires the token (in the loop below) BEFORE
	// spawning the worker; the worker releases it when it finishes.
	// Acquiring in the dispatcher (rather than inside the worker)
	// preserves input-order start semantics: workers can't race for
	// the token, because the dispatcher holds the only producer.
	sem := make(chan struct{}, concurrency)

	// done is closed once every dispatched worker has returned. We
	// select on it together with ctx.Done() below so a canceled
	// parent ctx can abandon the run rather than blocking on a
	// misbehaving check that ignores its own ctx.
	done := make(chan struct{})

	var wg sync.WaitGroup

	go func() {
		// Dispatcher: acquire a token then spawn the worker for each
		// check. If the parent ctx cancels before we've dispatched
		// every check, stop dispatching — the cancellation backfill
		// will fill the not-yet-dispatched slots.
		for i, c := range checks {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				// Parent canceled while we were waiting for a
				// worker slot. Bail out of the dispatch loop;
				// undispatched slots are filled by the freeze +
				// backfill block in Run after the select below.
				goto waitWorkers
			}
			wg.Add(1)
			go r.runOne(ctx, sem, &wg, state, i, c, timeout)
		}
	waitWorkers:
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Every dispatched worker finished normally.
	case <-ctx.Done():
		// Parent ctx canceled. Continue execution — the post-select
		// freeze + backfill below handles the partial-Report path.
	}

	// Freeze the result slice so any goroutine that finishes after
	// this point silently drops its write rather than racing the
	// caller's read of the returned Report. Backfill any incomplete
	// slots with the parent ctx error so the caller sees a fully
	// populated Results slice with no zero-value entries.
	state.mu.Lock()
	state.frozen = true
	now := time.Now().UTC()
	parentErr := ctx.Err()
	for i, c := range checks {
		if state.completed[i] {
			continue
		}
		state.results[i] = newCancelledResult(c, now, parentErr)
		state.completed[i] = true
	}
	state.mu.Unlock()

	rep.Summary = report.NewSummary(rep.Results)

	r.logf(ctx, slog.LevelInfo, "runner completed",
		slog.Int("total", rep.Summary.Total),
		slog.Int("pass", rep.Summary.Pass),
		slog.Int("fail", rep.Summary.Fail),
		slog.Int("skip", rep.Summary.Skip),
		slog.Int("error", rep.Summary.Error),
	)

	return rep
}

// runOne is the per-check worker. Releases its semaphore token when
// done, derives a per-check context with timeout, runs Applicable +
// Run under recover, and (if the run hasn't been frozen) records the
// result into the shared slice. wg.Done is always called via defer
// so a panic at any point still allows the run to terminate.
func (r *Runner) runOne(
	parentCtx context.Context,
	sem chan struct{},
	wg *sync.WaitGroup,
	state *runState,
	index int,
	c Check,
	timeout time.Duration,
) {
	defer wg.Done()
	defer func() { <-sem }()

	checkCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	startedAt := time.Now().UTC()
	res := r.executeCheck(checkCtx, c, startedAt, index)

	// Stamp DurationMS regardless of what the check returned. The
	// contract on Check.Run says implementations need not bother
	// computing duration; we ARE the source of truth for it.
	res.DurationMS = time.Since(startedAt).Milliseconds()

	state.mu.Lock()
	if !state.frozen && !state.completed[index] {
		state.results[index] = res
		state.completed[index] = true
	}
	frozen := state.frozen
	state.mu.Unlock()

	if frozen {
		// The Runner has already returned the (possibly partial)
		// Report to the caller. Don't log a "check completed" line —
		// the runner-completed log already fired. We're the leaked
		// goroutine the runner doc warns about.
		return
	}

	r.logf(parentCtx, slog.LevelInfo, "check completed",
		slog.String("check_id", res.CheckID),
		slog.String("state", string(res.State)),
		slog.String("severity", string(res.Severity)),
		slog.Int64("duration_ms", res.DurationMS),
	)
}

// executeCheck calls Applicable then (conditionally) Run, all under
// panic recovery. Returns the Result the caller should record. Always
// populates CheckID, Title, Severity, and StartedAt — even on panic
// or skip — so the result is structurally complete regardless of how
// the check terminated.
func (r *Runner) executeCheck(ctx context.Context, c Check, startedAt time.Time, index int) (res report.Result) {
	id := c.ID()
	title := c.Title()
	sev := c.Severity()

	// Pre-populate the result fields the Check might forget on the
	// error path. If Run returns its own Result (the happy path) we
	// overwrite below; if a panic blows past the call we still have
	// a structurally complete record.
	res = report.Result{
		CheckID:   id,
		Title:     title,
		Severity:  sev,
		StartedAt: startedAt,
		State:     report.StateError,
	}

	defer func() {
		if rec := recover(); rec != nil {
			res = report.Result{
				CheckID:   id,
				Title:     title,
				Severity:  sev,
				StartedAt: startedAt,
				State:     report.StateError,
				Detail:    fmt.Sprintf("check panicked: %v", rec),
				Err:       fmt.Sprintf("panic: %v", rec),
			}
			stack := captureStack()
			r.logf(ctx, slog.LevelError, "check panicked",
				slog.String("check_id", id),
				slog.Any("panic", rec),
				slog.Int("index", index),
				slog.String("stack", stack),
			)
		}
	}()

	ok, reason := c.Applicable(ctx)
	if !ok {
		res = report.Result{
			CheckID:   id,
			Title:     title,
			Severity:  sev,
			StartedAt: startedAt,
			State:     report.StateSkip,
			Detail:    reason,
		}
		return res
	}

	res = c.Run(ctx)
	// Defensive: a buggy check might return a zero-value Result. Make
	// sure the identity fields are populated so the report is never
	// missing them on a structurally complete (non-panic) path.
	if res.CheckID == "" {
		res.CheckID = id
	}
	if res.Title == "" {
		res.Title = title
	}
	if res.Severity == "" {
		res.Severity = sev
	}
	if res.StartedAt.IsZero() {
		res.StartedAt = startedAt
	}
	return res
}

// captureStack returns the current goroutine's stack trace as a
// string. We use runtime.Stack (not runtime/debug.Stack) so we can
// size the buffer ourselves and avoid the extra allocation that
// debug.Stack performs. The buffer size is stackBufBytes (64 KiB),
// which is large enough for any realistic check call chain.
func captureStack() string {
	buf := make([]byte, stackBufBytes)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// newCancelledResult constructs a StateError Result for a check that
// the Runner abandoned because the parent context was canceled. The
// Detail and Err strings include the parent ctx error (typically
// context.Canceled or context.DeadlineExceeded) so operators reading
// the Report can distinguish a normal cancellation from a timeout.
func newCancelledResult(c Check, when time.Time, parentErr error) report.Result {
	errMsg := "context canceled"
	if parentErr != nil {
		errMsg = fmt.Sprintf("check: parent context canceled: %v", parentErr)
	}
	return report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: when,
		State:     report.StateError,
		Detail:    fmt.Sprintf("runner abandoned check: %v", parentErr),
		Err:       errMsg,
	}
}

// logf is the nil-safe slog wrapper. Centralizes the `if r.Logger ==
// nil { return }` guard so callers don't sprinkle it everywhere.
func (r *Runner) logf(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr) {
	if r.Logger == nil {
		return
	}
	if !r.Logger.Enabled(ctx, level) {
		return
	}
	r.Logger.LogAttrs(ctx, level, msg, attrs...)
}
