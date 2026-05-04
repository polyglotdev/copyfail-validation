// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

// TestReport_WriteTo_FormatErrors verifies the two error paths of
// Report.WriteTo: unknown formats produce a wrapped ErrUnknownFormat
// (caller bug — bad CLI flag value), and known formats with no
// registered renderer produce a wrapped ErrRendererNotRegistered (build
// or import bug — see the blank-import contract documented on
// internal/render). Both paths must NOT write any bytes.
func TestReport_WriteTo_FormatErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		wantErr error
		name    string
		format  report.Format
	}{
		{
			name:    "unknown format yaml is rejected",
			format:  report.Format("yaml"),
			wantErr: report.ErrUnknownFormat,
		},
		{
			name:    "empty format is rejected",
			format:  report.Format(""),
			wantErr: report.ErrUnknownFormat,
		},
		{
			name:    "known format json with no registered renderer fails open",
			format:  report.FormatJSON,
			wantErr: report.ErrRendererNotRegistered,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			var rep report.Report
			var buf bytes.Buffer
			n, err := rep.WriteTo(&buf, tc.format)
			if !errors.Is(err, tc.wantErr) {
				subT.Fatalf("WriteTo(%q) err = %v, want %v", tc.format, err, tc.wantErr)
			}
			if n != 0 {
				subT.Errorf("WriteTo(%q) n = %d on error path, want 0", tc.format, n)
			}
			if buf.Len() != 0 {
				subT.Errorf("WriteTo(%q) wrote %d bytes on error path, want 0", tc.format, buf.Len())
			}
		})
	}
}

// TestReport_WriteTo_RegisteredRendererIsInvoked verifies the happy
// path: when a renderer is registered for a Format, WriteTo dispatches
// to it and returns the bytes-written + error from the renderer.
//
// Deliberately does not call t.Parallel(): it mutates the package-level
// renderer registry. The Snapshot/Restore pattern (added explicitly to
// support this kind of test) keeps the registry isolated for the rest
// of the test binary's lifetime — without it, a real Phase 4 renderer
// registered via internal/render's init() would be silently overwritten
// here and stay broken for every subsequent test.
func TestReport_WriteTo_RegisteredRendererIsInvoked(t *testing.T) {
	prev := report.SnapshotRenderers()
	t.Cleanup(func() { report.RestoreRenderers(prev) })

	const payload = "payload"
	called := false
	report.Register(report.FormatPrometheus, func(w io.Writer, _ report.Report) (int64, error) {
		called = true
		return io.Copy(w, bytes.NewReader([]byte(payload)))
	})

	var rep report.Report
	var buf bytes.Buffer
	n, err := rep.WriteTo(&buf, report.FormatPrometheus)
	if err != nil {
		t.Fatalf("WriteTo unexpected err = %v", err)
	}
	if !called {
		t.Error("registered renderer was not invoked")
	}
	if got := buf.String(); got != payload {
		t.Errorf("buf = %q, want %q", got, payload)
	}
	if n != int64(len(payload)) {
		t.Errorf("n = %d, want %d", n, len(payload))
	}
}

// TestSnapshotAndRestoreRenderers verifies the registry-isolation
// helpers in their own right: a Snapshot taken before a Register is
// untouched by subsequent registry mutations, and Restore replaces the
// live registry with the snapshot's contents (including by removing
// any renderer the snapshot did not contain).
func TestSnapshotAndRestoreRenderers(t *testing.T) {
	prev := report.SnapshotRenderers()
	t.Cleanup(func() { report.RestoreRenderers(prev) })

	// Start from a clean slate so this test is independent of the
	// surrounding test order.
	report.RestoreRenderers(map[report.Format]report.Renderer{})

	noopBefore := func(_ io.Writer, _ report.Report) (int64, error) { return 0, nil }
	report.Register(report.FormatJSON, noopBefore)

	snap := report.SnapshotRenderers()
	if _, ok := snap[report.FormatJSON]; !ok {
		t.Fatal("snapshot did not capture FormatJSON registration")
	}

	// Mutate the live registry AFTER the snapshot.
	report.Register(report.FormatHuman, noopBefore)

	if _, ok := snap[report.FormatHuman]; ok {
		t.Error("snapshot must be a copy; later mutation leaked into it")
	}

	report.RestoreRenderers(snap)

	// After restore, FormatJSON is present (was in the snapshot) but
	// FormatHuman is not (was added after the snapshot).
	var rep report.Report
	var buf bytes.Buffer
	if _, err := rep.WriteTo(&buf, report.FormatJSON); err != nil {
		t.Errorf("WriteTo(FormatJSON) after restore: %v", err)
	}
	if _, err := rep.WriteTo(&buf, report.FormatHuman); err == nil {
		t.Error("WriteTo(FormatHuman) after restore: expected ErrRendererNotRegistered, got nil")
	}
}
