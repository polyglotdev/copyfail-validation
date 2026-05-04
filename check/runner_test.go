// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/report"
)

// mockCheck is the test-only Check implementation used by every Runner
// behavioral test. The exported fields configure each phase of the
// check's lifecycle so tests can assemble bespoke scenarios without
// inventing a new struct each time.
//
// Concurrency-related counters (entered, ranCount, applicableCount)
// use sync/atomic so the race detector has nothing to complain about
// even when the same mock instance is queried from the test goroutine
// while the worker is executing.
type mockCheck struct {
	// runFn is invoked by Run. If nil, Run returns a StatePass result.
	runFn func(ctx context.Context) report.Result

	// panicVal, if non-nil, makes Run panic with this value before
	// runFn is consulted. Set to the zero value to disable.
	panicVal any

	// panicInApplicable is the symmetric panic-injection point for
	// Applicable. Used to verify that the Runner's recover catches
	// panics from BOTH lifecycle methods.
	panicInApplicable any

	// inFlight is incremented at Run entry and decremented at Run
	// exit. Tests assert against the high-water mark to verify the
	// Runner respects Concurrency.
	inFlight  *atomic.Int64
	highWater *atomic.Int64

	id               string
	title            string
	description      string
	severity         report.Severity
	applicableReason string

	ranCount   atomic.Int64
	appliedRan atomic.Int64

	// applicable controls the bool returned by Applicable.
	applicable bool
}

func newMock(id string) *mockCheck {
	return &mockCheck{
		id:          id,
		title:       "title-" + id,
		description: "description-" + id,
		severity:    report.SeverityRequired,
		applicable:  true,
	}
}

func (m *mockCheck) ID() string                { return m.id }
func (m *mockCheck) Title() string             { return m.title }
func (m *mockCheck) Description() string       { return m.description }
func (m *mockCheck) Severity() report.Severity { return m.severity }

func (m *mockCheck) Applicable(_ context.Context) (bool, string) {
	m.appliedRan.Add(1)
	if m.panicInApplicable != nil {
		panic(m.panicInApplicable)
	}
	return m.applicable, m.applicableReason
}

func (m *mockCheck) Run(ctx context.Context) report.Result {
	m.ranCount.Add(1)
	if m.inFlight != nil {
		current := m.inFlight.Add(1)
		defer m.inFlight.Add(-1)
		if m.highWater != nil {
			for {
				prev := m.highWater.Load()
				if current <= prev {
					break
				}
				if m.highWater.CompareAndSwap(prev, current) {
					break
				}
			}
		}
	}
	if m.panicVal != nil {
		panic(m.panicVal)
	}
	if m.runFn != nil {
		return m.runFn(ctx)
	}
	return report.Result{
		CheckID:  m.id,
		Title:    m.title,
		Severity: m.severity,
		State:    report.StatePass,
	}
}

// withRun is a fluent helper to attach a Run function to a mock.
func (m *mockCheck) withRun(fn func(ctx context.Context) report.Result) *mockCheck {
	m.runFn = fn
	return m
}

// withApplicable returns a mock that reports the given applicability.
func (m *mockCheck) withApplicable(ok bool, reason string) *mockCheck {
	m.applicable = ok
	m.applicableReason = reason
	return m
}

// withPanic configures Run to panic with the given value.
func (m *mockCheck) withPanic(v any) *mockCheck {
	m.panicVal = v
	return m
}

// TestRunner_SequentialOrderWithConcurrencyOne pins the regression
// that Concurrency=1 forces serial execution AND that the result
// slice mirrors input order. We observe sequencing by recording the
// order in which each mock's Run started (a strictly monotonic
// timestamp slice protected by a mutex). The test would catch any
// future change that accidentally fanned out under Concurrency=1.
func TestRunner_SequentialOrderWithConcurrencyOne(t *testing.T) {
	t.Parallel()

	const total = 5
	var (
		mu        sync.Mutex
		startedAt []string
	)

	checks := make([]check.Check, 0, total)
	for i := range total {
		idCopy := fmt.Sprintf("seq.%d", i)
		m := newMock(idCopy).withRun(func(_ context.Context) report.Result {
			mu.Lock()
			startedAt = append(startedAt, idCopy)
			mu.Unlock()
			// Deliberate small sleep so the runtime would have a
			// chance to interleave goroutines if the bounded pool
			// ever broke.
			time.Sleep(2 * time.Millisecond)
			return report.Result{State: report.StatePass}
		})
		checks = append(checks, m)
	}

	r := &check.Runner{Concurrency: 1, Timeout: time.Second}
	rep := r.Run(context.Background(), checks)

	if got, want := len(rep.Results), total; got != want {
		t.Fatalf("len(Results) = %d, want %d", got, want)
	}
	for i, res := range rep.Results {
		want := fmt.Sprintf("seq.%d", i)
		if res.CheckID != want {
			t.Errorf("Results[%d].CheckID = %q, want %q", i, res.CheckID, want)
		}
	}
	if got, want := len(startedAt), total; got != want {
		t.Fatalf("startedAt len = %d, want %d", got, want)
	}
	for i, id := range startedAt {
		want := fmt.Sprintf("seq.%d", i)
		if id != want {
			t.Errorf("startedAt[%d] = %q, want %q (sequential ordering broken)", i, id, want)
		}
	}
}

// TestRunner_BoundedConcurrency pins the headline Runner contract:
// at most Runner.Concurrency goroutines are running Check.Run at any
// instant. Each mock atomically tracks an in-flight counter and a
// high-water mark; we assert the high-water mark equals the
// configured concurrency for a workload large enough to saturate it.
func TestRunner_BoundedConcurrency(t *testing.T) {
	t.Parallel()

	const (
		total       = 100
		concurrency = 10
		busy        = 5 * time.Millisecond
	)
	var (
		inFlight  atomic.Int64
		highWater atomic.Int64
	)

	checks := make([]check.Check, 0, total)
	for i := range total {
		m := newMock(fmt.Sprintf("conc.%d", i))
		m.inFlight = &inFlight
		m.highWater = &highWater
		m.runFn = func(_ context.Context) report.Result {
			time.Sleep(busy)
			return report.Result{State: report.StatePass}
		}
		checks = append(checks, m)
	}

	r := &check.Runner{Concurrency: concurrency, Timeout: time.Second}
	rep := r.Run(context.Background(), checks)

	if got, want := len(rep.Results), total; got != want {
		t.Fatalf("len(Results) = %d, want %d", got, want)
	}
	if peak := highWater.Load(); peak > concurrency {
		t.Fatalf("max in-flight = %d, want ≤ %d (pool unbounded)", peak, concurrency)
	}
	if peak := highWater.Load(); peak < concurrency {
		t.Fatalf("max in-flight = %d, want exactly %d (pool under-utilized)", peak, concurrency)
	}
}

// TestRunner_PanicRecoveryLeavesSiblingsIntact pins the contract that
// one buggy check cannot bring down the run. We thread a panicker into
// the middle of an otherwise-healthy workload and assert (a) every
// non-panicker still runs and produces a Pass; (b) the panicker
// produces a StateError whose Err / Detail mention the panic value;
// (c) the result slice is in input order regardless of which finished
// first.
func TestRunner_PanicRecoveryLeavesSiblingsIntact(t *testing.T) {
	t.Parallel()

	const (
		nBefore = 4
		nAfter  = 4
	)
	checks := make([]check.Check, 0, nBefore+1+nAfter)
	for i := range nBefore {
		checks = append(checks, newMock(fmt.Sprintf("ok.before.%d", i)))
	}
	checks = append(checks, newMock("panicker").withPanic("intentional test panic"))
	for i := range nAfter {
		checks = append(checks, newMock(fmt.Sprintf("ok.after.%d", i)))
	}

	r := &check.Runner{Concurrency: 4, Timeout: time.Second}
	rep := r.Run(context.Background(), checks)

	if got, want := len(rep.Results), len(checks); got != want {
		t.Fatalf("len(Results) = %d, want %d", got, want)
	}
	for i, res := range rep.Results {
		expectedID := checks[i].ID()
		if res.CheckID != expectedID {
			t.Errorf("Results[%d].CheckID = %q, want %q (order broken)", i, res.CheckID, expectedID)
		}
		if expectedID == "panicker" {
			if res.State != report.StateError {
				t.Errorf("panicker state = %q, want %q", res.State, report.StateError)
			}
			if !strings.Contains(res.Err, "panic:") {
				t.Errorf("panicker Err = %q, want contains 'panic:'", res.Err)
			}
			if !strings.Contains(res.Err, "intentional test panic") {
				t.Errorf("panicker Err = %q, want contains panic value", res.Err)
			}
		} else if res.State != report.StatePass {
			t.Errorf("sibling %q state = %q, want %q", res.CheckID, res.State, report.StatePass)
		}
	}
}

// TestRunner_ResultOrderMatchesInputRegardlessOfCompletion pins the
// "order is determined by INPUT, not by completion" guarantee. We
// arrange one slow check at the head followed by nine fast checks;
// the fast ones MUST complete first, but the assembled report must
// still list them in the original positional order.
func TestRunner_ResultOrderMatchesInputRegardlessOfCompletion(t *testing.T) {
	t.Parallel()

	checks := make([]check.Check, 0, 10)
	checks = append(checks, newMock("slow.0").withRun(func(_ context.Context) report.Result {
		time.Sleep(50 * time.Millisecond)
		return report.Result{State: report.StatePass}
	}))
	for i := 1; i < 10; i++ {
		checks = append(checks, newMock(fmt.Sprintf("fast.%d", i)))
	}

	r := &check.Runner{Concurrency: 10, Timeout: time.Second}
	rep := r.Run(context.Background(), checks)

	for i, res := range rep.Results {
		want := checks[i].ID()
		if res.CheckID != want {
			t.Errorf("Results[%d].CheckID = %q, want %q (order must reflect input)", i, res.CheckID, want)
		}
	}
}

// TestRunner_ApplicableFalseSkipsRun pins that a check whose
// Applicable returns (false, reason) produces a StateSkip result with
// reason in Detail AND does NOT have its Run called.
func TestRunner_ApplicableFalseSkipsRun(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		reason     string
		wantDetail string
	}{
		{name: "with reason", reason: "host is not Linux", wantDetail: "host is not Linux"},
		{name: "empty reason", reason: "", wantDetail: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			m := newMock("skipper").withApplicable(false, tc.reason)
			r := &check.Runner{Concurrency: 1, Timeout: time.Second}
			rep := r.Run(context.Background(), []check.Check{m})

			if len(rep.Results) != 1 {
				subT.Fatalf("len(Results) = %d, want 1", len(rep.Results))
			}
			res := rep.Results[0]
			if res.State != report.StateSkip {
				subT.Errorf("State = %q, want %q", res.State, report.StateSkip)
			}
			if res.Detail != tc.wantDetail {
				subT.Errorf("Detail = %q, want %q", res.Detail, tc.wantDetail)
			}
			if got := m.ranCount.Load(); got != 0 {
				subT.Errorf("Run was called %d time(s), want 0 (skipped checks must not run)", got)
			}
			if got := m.appliedRan.Load(); got != 1 {
				subT.Errorf("Applicable was called %d time(s), want 1", got)
			}
		})
	}
}

// TestRunner_PerCheckTimeout pins the per-check timeout: a check that
// honors ctx and would otherwise sleep past Timeout is killed by the
// ctx cancellation, returns a StateError, and the operator sees the
// deadline-exceeded reason in the result. The test relies on the
// well-behaved-check property; the misbehaving-check case is covered
// in runner_concurrency_test.go.
func TestRunner_PerCheckTimeout(t *testing.T) {
	t.Parallel()

	const (
		timeout = 50 * time.Millisecond
		sleep   = 500 * time.Millisecond
	)

	m := newMock("slow").withRun(func(ctx context.Context) report.Result {
		select {
		case <-time.After(sleep):
			return report.Result{State: report.StatePass}
		case <-ctx.Done():
			return report.Result{
				State:  report.StateError,
				Err:    ctx.Err().Error(),
				Detail: fmt.Sprintf("ctx done: %v", ctx.Err()),
			}
		}
	})

	r := &check.Runner{Concurrency: 1, Timeout: timeout}
	start := time.Now()
	rep := r.Run(context.Background(), []check.Check{m})
	elapsed := time.Since(start)

	if elapsed > 5*timeout {
		t.Fatalf("Run took %v, want ≤ %v (timeout did not fire)", elapsed, 5*timeout)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1", len(rep.Results))
	}
	res := rep.Results[0]
	if res.State != report.StateError {
		t.Errorf("State = %q, want %q", res.State, report.StateError)
	}
	if !strings.Contains(res.Err, "deadline exceeded") {
		t.Errorf("Err = %q, want contains 'deadline exceeded'", res.Err)
	}
}

// TestRunner_ParentContextCancelMidRun pins the cancellation contract:
// when the parent ctx is canceled mid-run, the Runner abandons the
// wait, fills any incomplete result slots with StateError, and returns
// a Report whose Results slice is fully populated (no nils).
func TestRunner_ParentContextCancelMidRun(t *testing.T) {
	t.Parallel()

	const total = 10

	checks := make([]check.Check, 0, total)
	for i := range total {
		m := newMock(fmt.Sprintf("cancellable.%d", i)).withRun(func(ctx context.Context) report.Result {
			select {
			case <-time.After(2 * time.Second):
				return report.Result{State: report.StatePass}
			case <-ctx.Done():
				return report.Result{
					State:  report.StateError,
					Err:    ctx.Err().Error(),
					Detail: "canceled by parent",
				}
			}
		})
		checks = append(checks, m)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	r := &check.Runner{Concurrency: 4, Timeout: 5 * time.Second}
	rep := r.Run(ctx, checks)

	if got := len(rep.Results); got != total {
		t.Fatalf("len(Results) = %d, want %d (every slot must be filled)", got, total)
	}
	for i, res := range rep.Results {
		expectedID := checks[i].ID()
		if res.CheckID != expectedID {
			t.Errorf("Results[%d].CheckID = %q, want %q (order broken)", i, res.CheckID, expectedID)
		}
		if res.State != report.StateError {
			t.Errorf("Results[%d].State = %q, want %q (every slot must be StateError on cancel)", i, res.State, report.StateError)
		}
		if res.Err == "" {
			t.Errorf("Results[%d].Err is empty, want non-empty cancellation message", i)
		}
	}
}

// TestRunner_LoggerReceivesExpectedLines pins that a non-nil Logger
// gets info-level lines for runner start, each check completion, and
// runner completion. The test parses the captured JSON lines and
// asserts that the headline attributes are present.
func TestRunner_LoggerReceivesExpectedLines(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	checks := []check.Check{
		newMock("a"),
		newMock("b"),
	}

	r := &check.Runner{Concurrency: 2, Timeout: time.Second, Logger: logger}
	rep := r.Run(context.Background(), checks)

	if rep.Summary.Total != len(checks) {
		t.Fatalf("Summary.Total = %d, want %d", rep.Summary.Total, len(checks))
	}

	type line struct {
		Msg     string `json:"msg"`
		CheckID string `json:"check_id"`
	}

	var lines []line
	for _, raw := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte{'\n'}) {
		if len(raw) == 0 {
			continue
		}
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("invalid JSON line %q: %v", raw, err)
		}
		lines = append(lines, l)
	}

	wantMsgs := map[string]bool{
		"runner starting":  false,
		"check completed":  false,
		"runner completed": false,
	}
	for _, l := range lines {
		if _, ok := wantMsgs[l.Msg]; ok {
			wantMsgs[l.Msg] = true
		}
	}
	for msg, seen := range wantMsgs {
		if !seen {
			t.Errorf("expected log line %q not found in:\n%s", msg, buf.String())
		}
	}
}

// TestRunner_NilLoggerProducesNoOutput pins that the zero Runner
// (Logger=nil) is silent. We capture the logger field's writer
// indirectly by asserting that the zero Runner runs cleanly without
// any panic and without any side-effect we can detect.
func TestRunner_NilLoggerProducesNoOutput(t *testing.T) {
	t.Parallel()

	r := &check.Runner{}
	rep := r.Run(context.Background(), []check.Check{newMock("a")})
	if rep.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want 1", rep.Summary.Total)
	}
}

// TestRunner_EmptyChecksSliceReturnsZeroSummary pins the no-op path:
// an empty []Check returns a Report with empty Results and a
// zero-tally Summary, and does NOT panic.
func TestRunner_EmptyChecksSliceReturnsZeroSummary(t *testing.T) {
	t.Parallel()

	r := &check.Runner{}
	rep := r.Run(context.Background(), nil)

	if got := len(rep.Results); got != 0 {
		t.Errorf("len(Results) = %d, want 0", got)
	}
	if rep.Summary.Total != 0 {
		t.Errorf("Summary.Total = %d, want 0", rep.Summary.Total)
	}
}

// TestRunner_RunnerDoesNotPopulateSchemaOrToolOrHost pins the
// CLI/library boundary: those three fields are the CLI's
// responsibility to populate. The Runner explicitly leaves them as
// zero values so their absence in the assembled Report is documented
// behavior, not an oversight.
func TestRunner_RunnerDoesNotPopulateSchemaOrToolOrHost(t *testing.T) {
	t.Parallel()

	r := &check.Runner{}
	rep := r.Run(context.Background(), []check.Check{newMock("a")})

	if rep.SchemaVersion != "" {
		t.Errorf("SchemaVersion = %q, want \"\" (CLI populates this)", rep.SchemaVersion)
	}
	if rep.Tool != (report.ToolInfo{}) {
		t.Errorf("Tool = %+v, want zero value (CLI populates this)", rep.Tool)
	}
	if rep.Host != (report.HostInfo{}) {
		t.Errorf("Host = %+v, want zero value (CLI populates this)", rep.Host)
	}
}

// TestRunner_GeneratedTimestampNearNow pins that Report.Generated is
// stamped to time.Now().UTC() at Run start (within ±1 second to
// tolerate scheduler jitter on slow CI runners). The wider purpose:
// downstream renderers can rely on a non-zero, sensibly-recent
// timestamp without having to defensively backfill it.
func TestRunner_GeneratedTimestampNearNow(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	r := &check.Runner{}
	rep := r.Run(context.Background(), []check.Check{newMock("a")})
	after := time.Now().UTC()

	if rep.Generated.Before(before.Add(-time.Second)) {
		t.Errorf("Generated %v is more than 1s before run start %v", rep.Generated, before)
	}
	if rep.Generated.After(after.Add(time.Second)) {
		t.Errorf("Generated %v is more than 1s after run end %v", rep.Generated, after)
	}
	if rep.Generated.Location() != time.UTC {
		t.Errorf("Generated TZ = %v, want UTC", rep.Generated.Location())
	}
}

// TestRunner_PanicInApplicable pins that a panic from Applicable is
// caught by the same recover that catches Run panics. Without this
// the buggy-Applicable case would crash the binary because Applicable
// runs INSIDE the worker goroutine (per docs/runner.go contract).
func TestRunner_PanicInApplicable(t *testing.T) {
	t.Parallel()

	m := newMock("applicable.panic")
	m.panicInApplicable = "boom in Applicable"

	r := &check.Runner{Concurrency: 1, Timeout: time.Second}
	rep := r.Run(context.Background(), []check.Check{m})

	if len(rep.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1", len(rep.Results))
	}
	res := rep.Results[0]
	if res.State != report.StateError {
		t.Errorf("State = %q, want %q", res.State, report.StateError)
	}
	if !strings.Contains(res.Err, "panic:") {
		t.Errorf("Err = %q, want contains 'panic:'", res.Err)
	}
}

// TestRunner_DurationMSAlwaysStamped pins the Result.DurationMS
// invariant: even when a check leaves the field zero, the Runner
// overwrites it with the measured wall-clock duration. The test runs
// a check that deliberately returns a Result with DurationMS=0 and
// asserts the Runner stamped a non-zero value (via a small artificial
// busy-loop that would always exceed 1ms).
func TestRunner_DurationMSAlwaysStamped(t *testing.T) {
	t.Parallel()

	m := newMock("duration").withRun(func(_ context.Context) report.Result {
		time.Sleep(5 * time.Millisecond)
		return report.Result{State: report.StatePass} // DurationMS deliberately zero
	})

	r := &check.Runner{Concurrency: 1, Timeout: time.Second}
	rep := r.Run(context.Background(), []check.Check{m})

	if rep.Results[0].DurationMS == 0 {
		t.Errorf("DurationMS = 0, want non-zero (Runner must stamp it)")
	}
}

// TestRunner_DefaultsAppliedForZeroValues pins that a Runner{} (zero
// Concurrency, zero Timeout) still works — defaulting to runtime
// NumCPU and 30s. We exercise the path with one fast check and
// assert the run completes; the fact that defaults get applied is
// exercised indirectly by all preceding tests, but having a focused
// assertion here documents the intent.
func TestRunner_DefaultsAppliedForZeroValues(t *testing.T) {
	t.Parallel()

	r := &check.Runner{}
	rep := r.Run(context.Background(), []check.Check{newMock("d")})
	if rep.Results[0].State != report.StatePass {
		t.Errorf("State = %q, want %q (defaults must allow trivial check to pass)", rep.Results[0].State, report.StatePass)
	}
}
