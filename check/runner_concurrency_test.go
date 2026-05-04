// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check_test

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestRunner_BuggyCheckIgnoresContextRunnerStillReturns is the
// regression test for the documented "buggy check leaks a goroutine
// but the Runner returns" cancellation-semantics rule on the Runner
// type. We ship a check that deliberately ignores ctx.Done() AND
// sleeps for ~30 minutes; the Runner's per-check timeout fires; the
// caller-supplied parent cancellation lets Run return promptly even
// though the buggy goroutine is still alive in the background.
//
// The test would HANG if the runner waited unconditionally for the
// buggy goroutine; we cap the wall-clock time with t.Cleanup +
// time.AfterFunc so a regression is loud (test failure) rather than
// silent (CI hang followed by 10-minute timeout).
//
// The "leaked" goroutine is allowed by the Runner contract; we
// don't assert on the post-Run goroutine count here (that's the
// goroutine-leak test below, which uses well-behaved checks).
func TestRunner_BuggyCheckIgnoresContextRunnerStillReturns(t *testing.T) {
	t.Parallel()

	// Hard wall-clock timeout: if the runner doesn't return within
	// 2s the test fails loudly. Without this, a regression that
	// waited unconditionally for the leaked goroutine would hang
	// the suite for the full 30-minute mock sleep.
	const hardLimit = 2 * time.Second
	finished := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(hardLimit):
			t.Fatalf("Runner.Run did not return within %v despite ctx cancel — buggy-check leak may now block the runner", hardLimit)
		}
	})

	// allowExit lets the buggy goroutine eventually exit so the
	// test process can shut down cleanly. Without it, the test
	// passes but the process holds onto the goroutine until the
	// next GC cycle's stack scan, complicating cleanup. The
	// channel is closed in t.Cleanup AFTER the success signal so
	// the leak is real for the duration of the assertion.
	allowExit := make(chan struct{})
	t.Cleanup(func() { close(allowExit) })

	buggy := newMock("buggy.ignores.ctx").withRun(func(_ context.Context) report.Result {
		// Deliberately ignore ctx. Wait for the test cleanup to
		// release us — without this the goroutine would live for
		// ~30 minutes and the test process couldn't terminate.
		<-allowExit
		return report.Result{State: report.StatePass}
	})

	parent, cancel := context.WithCancel(context.Background())

	// Cancel the parent shortly after the runner starts. The buggy
	// check ignores the cancellation; the runner's select must
	// detect ctx.Done and return without waiting.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	r := &check.Runner{Concurrency: 1, Timeout: 10 * time.Minute}
	start := time.Now()
	rep := r.Run(parent, []check.Check{buggy})
	close(finished)
	elapsed := time.Since(start)

	if elapsed > hardLimit {
		t.Fatalf("Runner.Run took %v, want ≤ %v", elapsed, hardLimit)
	}
	if got := len(rep.Results); got != 1 {
		t.Fatalf("len(Results) = %d, want 1", got)
	}
	if rep.Results[0].State != report.StateError {
		t.Errorf("State = %q, want %q", rep.Results[0].State, report.StateError)
	}
}

// TestRunner_NoRaceUnderHeavyParallelism sustains a thousand checks
// across four workers; the test fails (under -race) if any of the
// shared-state coordination paths re-introduce a race. The check
// bodies do trivial atomic increments to the same counter to give
// the race detector something to catch should the synchronization
// regression happen.
func TestRunner_NoRaceUnderHeavyParallelism(t *testing.T) {
	t.Parallel()

	const total = 1000
	var counter atomic.Int64

	checks := make([]check.Check, 0, total)
	for i := range total {
		checks = append(checks, newMock(fmt.Sprintf("heavy.%d", i)).withRun(func(_ context.Context) report.Result {
			counter.Add(1)
			return report.Result{State: report.StatePass}
		}))
	}

	r := &check.Runner{Concurrency: 4, Timeout: 5 * time.Second}
	rep := r.Run(context.Background(), checks)

	if got := len(rep.Results); got != total {
		t.Fatalf("len(Results) = %d, want %d", got, total)
	}
	if got := counter.Load(); got != int64(total) {
		t.Errorf("counter = %d, want %d", got, total)
	}
	for i, res := range rep.Results {
		if res.State != report.StatePass {
			t.Errorf("Results[%d].State = %q, want %q", i, res.State, report.StatePass)
			break
		}
	}
}

// TestRunner_NoGoroutineLeak pins that running the Runner and waiting
// for it to return does not durably grow the goroutine population. We
// take baseline + after counts with a small tolerance to absorb
// runtime jitter (the test runner's own goroutines, slog handler
// flush goroutines, etc.) and assert convergence after a brief
// settle period.
//
// The test deliberately does NOT exercise the cancellation path —
// that path is documented to leak goroutines for misbehaving checks
// (see TestRunner_BuggyCheckIgnoresContextRunnerStillReturns).
// Here every check is well-behaved: it returns promptly.
func TestRunner_NoGoroutineLeak(t *testing.T) {
	t.Parallel()

	const (
		iterations = 5
		batchSize  = 50
		// tolerance is the number of "extra" goroutines we accept
		// after the runs as scheduler / runtime overhead. The Go
		// runtime can hold onto worker goroutines for short periods
		// after they exit; ±5 covers that.
		tolerance = 5
	)

	checks := make([]check.Check, 0, batchSize)
	for i := range batchSize {
		checks = append(checks, newMock(fmt.Sprintf("leak.%d", i)))
	}

	settle := func() {
		runtime.Gosched()
		// A brief sleep gives the runtime time to actually reap
		// transient goroutines. The exact value isn't load-bearing;
		// 50ms is empirically enough on a busy laptop and CI runner.
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
	}

	settle()
	baseline := runtime.NumGoroutine()

	for i := range iterations {
		r := &check.Runner{Concurrency: 8, Timeout: time.Second}
		_ = r.Run(context.Background(), checks)
		settle()

		now := runtime.NumGoroutine()
		if now > baseline+tolerance {
			t.Errorf("iteration %d: NumGoroutine = %d, baseline = %d, tolerance = %d", i, now, baseline, tolerance)
		}
	}
}

// TestRunner_DispatcherStopsOnCancelDuringSlotWait pins the
// dispatcher's behavior when the parent ctx cancels WHILE the
// dispatcher is blocked acquiring a worker slot. Setup:
//   - Concurrency=1 so the second dispatch must wait.
//   - First check holds its slot for 500ms ignoring ctx (so
//     cancellation cannot release the slot via timeout).
//   - Cancel the parent at t=50ms — dispatcher should bail out
//     and the second check's result is filled by the cancel
//     backfill, not by an actual Run invocation.
//
// Without the dispatcher's select-with-ctx the cancellation would
// not propagate until the first check completed, defeating the
// "Runner always returns" guarantee.
func TestRunner_DispatcherStopsOnCancelDuringSlotWait(t *testing.T) {
	t.Parallel()

	finished := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Fatalf("Runner did not return within 2s — dispatcher may be stuck waiting for a slot")
		}
	})

	allowExit := make(chan struct{})
	t.Cleanup(func() { close(allowExit) })

	first := newMock("first.holds.slot").withRun(func(_ context.Context) report.Result {
		<-allowExit
		return report.Result{State: report.StatePass}
	})
	second := newMock("second.never.runs")

	parent, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	r := &check.Runner{Concurrency: 1, Timeout: 10 * time.Minute}
	rep := r.Run(parent, []check.Check{first, second})
	close(finished)

	if got := len(rep.Results); got != 2 {
		t.Fatalf("len(Results) = %d, want 2", got)
	}
	// The second slot must be a cancel-backfilled StateError.
	if rep.Results[1].State != report.StateError {
		t.Errorf("Results[1].State = %q, want %q (must be backfilled on cancel)", rep.Results[1].State, report.StateError)
	}
	if rep.Results[1].CheckID != "second.never.runs" {
		t.Errorf("Results[1].CheckID = %q, want %q", rep.Results[1].CheckID, "second.never.runs")
	}
	// Crucially, the second mock's Run must NOT have been invoked.
	if got := second.ranCount.Load(); got != 0 {
		t.Errorf("second.ranCount = %d, want 0 (dispatcher must not have launched it)", got)
	}
}
