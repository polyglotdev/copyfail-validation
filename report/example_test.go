// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/polyglotdev/copyfail-validation/report"
)

// ExampleState_SARIFKind shows how a State value maps to a SARIF v2.1.0
// result.kind string. Unknown / future State values fail safe to "open"
// so unexpected runtime values are never silently classified as "pass".
func ExampleState_SARIFKind() {
	for _, s := range []report.State{
		report.StatePass,
		report.StateFail,
		report.StateSkip,
		report.StateError,
		report.State("future-value"),
	} {
		fmt.Printf("%-13s -> %s\n", s, s.SARIFKind())
	}
	// Output:
	// pass          -> pass
	// fail          -> fail
	// skip          -> notApplicable
	// error         -> open
	// future-value  -> open
}

// ExampleSeverity_IsRequired shows why callers should prefer the
// IsRequired method over a direct equality check: future Severity values
// can extend the "required-class" set without requiring every consumer
// to update.
func ExampleSeverity_IsRequired() {
	for _, sev := range []report.Severity{
		report.SeverityRequired,
		report.SeverityAdvisory,
		report.Severity(""),
	} {
		fmt.Printf("%-9s required=%t\n", sev, sev.IsRequired())
	}
	// Output:
	// required  required=true
	// advisory  required=false
	//           required=false
}

// ExampleParseFormat shows the case-insensitive parser and its explicit
// rejection of the empty string. Callers (typically the CLI flag parser)
// MUST pick a default value before invoking ParseFormat — the parser
// will not silently choose one for them.
func ExampleParseFormat() {
	for _, in := range []string{"json", "SARIF", "yaml", ""} {
		f, err := report.ParseFormat(in)
		if err != nil {
			fmt.Printf("%-7q -> error: %v\n", in, errors.Is(err, report.ErrUnknownFormat))
			continue
		}
		fmt.Printf("%-7q -> %s\n", in, f)
	}
	// Output:
	// "json"  -> json
	// "SARIF" -> sarif
	// "yaml"  -> error: true
	// ""      -> error: true
}

// ExampleNewSummary shows how the Summary aggregate is computed from a
// Results slice. Note that required Skip is intentionally NOT counted in
// the Required bucket — only Required.Pass, Required.Fail, and
// Required.Error contribute to the process exit code (spec §6).
func ExampleNewSummary() {
	results := []report.Result{
		{State: report.StatePass, Severity: report.SeverityRequired},
		{State: report.StateFail, Severity: report.SeverityRequired},
		{State: report.StateError, Severity: report.SeverityRequired},
		{State: report.StateSkip, Severity: report.SeverityRequired}, // not in Required bucket
		{State: report.StatePass, Severity: report.SeverityAdvisory},
	}
	s := report.NewSummary(results)
	fmt.Printf("Total=%d Pass=%d Fail=%d Skip=%d Error=%d\n", s.Total, s.Pass, s.Fail, s.Skip, s.Error)
	fmt.Printf("Required: Pass=%d Fail=%d Error=%d\n", s.Required.Pass, s.Required.Fail, s.Required.Error)
	// Output:
	// Total=5 Pass=2 Fail=1 Skip=1 Error=1
	// Required: Pass=1 Fail=1 Error=1
}

// ExampleReport_WriteTo_unknownFormat shows the error that callers see
// when they pass a Format value the package does not recognize. This is
// the same wrapped sentinel ParseFormat returns, so a consumer that
// handles ErrUnknownFormat once handles both pathways.
func ExampleReport_WriteTo_unknownFormat() {
	rep := report.Report{SchemaVersion: report.SchemaVersionCurrent}
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.Format("yaml"))
	fmt.Println(errors.Is(err, report.ErrUnknownFormat))
	// Output:
	// true
}

// ExampleReport_WriteTo_unregisteredRenderer shows the error that
// callers see when the requested Format is recognized but no renderer
// is registered for it. In production builds the internal/render
// package's init() registers all four renderers; in tests that import
// only "report", consumers will see this error and the most likely
// cause is a missing blank import:
//
//	import _ "github.com/polyglotdev/copyfail-validation/internal/render"
func ExampleReport_WriteTo_unregisteredRenderer() {
	rep := report.Report{SchemaVersion: report.SchemaVersionCurrent}
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.FormatJSON)
	fmt.Println(errors.Is(err, report.ErrRendererNotRegistered))
	// Output:
	// true
}

// ExampleRegister shows how a custom Format would be wired in by
// in-tree consumers (typically internal/render). This pattern lets the
// report package stay a leaf in the dependency graph: it owns the
// registry but knows nothing about any concrete renderer.
//
// Production code (internal/render's init) calls Register exactly once
// per Format. Tests should use SnapshotRenderers + RestoreRenderers
// (see ExampleSnapshotRenderers) to avoid leaving the registry mutated
// for the rest of the test binary.
func ExampleRegister() {
	prev := report.SnapshotRenderers()
	defer report.RestoreRenderers(prev)

	const customFormat report.Format = "json"
	report.Register(customFormat, func(w io.Writer, rep report.Report) (int64, error) {
		b, err := json.Marshal(rep)
		if err != nil {
			return 0, err
		}
		n, err := w.Write(b)
		return int64(n), err
	})

	rep := report.Report{
		SchemaVersion: report.SchemaVersionCurrent,
		Generated:     time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC),
	}
	var buf bytes.Buffer
	if _, err := rep.WriteTo(&buf, customFormat); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("wrote", buf.Len(), "bytes of JSON")
	// Output:
	// wrote 327 bytes of JSON
}

// ExampleSnapshotRenderers shows the canonical isolation pattern for
// tests that need to register a temporary renderer: snapshot before,
// restore via t.Cleanup (or defer in this example) after. Without this,
// the test would silently overwrite a real renderer for the rest of
// the test binary's lifetime, breaking unrelated downstream tests.
func ExampleSnapshotRenderers() {
	// Save current state.
	prev := report.SnapshotRenderers()
	defer report.RestoreRenderers(prev)

	// Install a stub for the duration of this scope.
	report.Register(report.FormatHuman, func(_ io.Writer, _ report.Report) (int64, error) {
		return 0, nil
	})
	fmt.Println("renderer installed; will be removed by defer")
	// Output:
	// renderer installed; will be removed by defer
}
