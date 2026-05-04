// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package check_test

import (
	"context"
	"fmt"
	"time"

	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/report"
)

// okCheck is a minimal Check used by ExampleRunner_Run and
// ExampleCheck. Real checks live under preset/<name>/ and shell out
// to internal/exec; this stub deliberately returns a static Pass so
// the example output is byte-stable.
type okCheck struct {
	id  string
	sev report.Severity
}

func (c okCheck) ID() string                                { return c.id }
func (c okCheck) Title() string                             { return "OK: " + c.id }
func (c okCheck) Description() string                       { return "Always passes; used in package examples." }
func (c okCheck) Severity() report.Severity                 { return c.sev }
func (c okCheck) Applicable(context.Context) (bool, string) { return true, "" }
func (c okCheck) Run(context.Context) report.Result {
	return report.Result{State: report.StatePass}
}

// ExampleCheck shows the smallest possible Check implementation. It
// exists to anchor the "what does a Check look like end-to-end?"
// question in godoc; presets adopt the same pattern but delegate the
// actual probing to internal/* packages.
func ExampleCheck() {
	var c check.Check = okCheck{id: "demo.pass", sev: report.SeverityAdvisory}
	fmt.Println("ID:", c.ID())
	fmt.Println("Severity:", c.Severity())
	ok, _ := c.Applicable(context.Background())
	fmt.Println("Applicable:", ok)
	res := c.Run(context.Background())
	fmt.Println("State:", res.State)
	// Output:
	// ID: demo.pass
	// Severity: advisory
	// Applicable: true
	// State: pass
}

// ExampleRunner_Run shows the canonical caller pattern: build a
// Runner with explicit Concurrency + Timeout, run two trivial checks,
// and print the assembled Summary. Real callers also set
// Runner.Logger for production observability; the example omits it
// so the printed bytes don't depend on slog output.
func ExampleRunner_Run() {
	checks := []check.Check{
		okCheck{id: "demo.first", sev: report.SeverityRequired},
		okCheck{id: "demo.second", sev: report.SeverityAdvisory},
	}

	r := &check.Runner{
		Concurrency: 2,
		Timeout:     time.Second,
	}
	rep := r.Run(context.Background(), checks)

	fmt.Printf("Total=%d Pass=%d Fail=%d Skip=%d Error=%d\n",
		rep.Summary.Total, rep.Summary.Pass, rep.Summary.Fail,
		rep.Summary.Skip, rep.Summary.Error)
	for _, res := range rep.Results {
		fmt.Printf("%-12s %s\n", res.CheckID, res.State)
	}
	// Output:
	// Total=2 Pass=2 Fail=0 Skip=0 Error=0
	// demo.first   pass
	// demo.second  pass
}

// ExampleRunner shows the zero-value Runner: Concurrency defaults to
// runtime.NumCPU(), Timeout defaults to 30 seconds, Logger defaults
// to nil (silent). The example deliberately runs zero checks so the
// printed bytes are stable across machines (NumCPU varies by host).
func ExampleRunner() {
	var r check.Runner
	rep := r.Run(context.Background(), nil)
	fmt.Printf("Total=%d\n", rep.Summary.Total)
	// Output:
	// Total=0
}
