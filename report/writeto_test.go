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
// renderer registry by calling Register, and the registry has no
// Unregister. Running it sequentially (and using a Format key that the
// FormatErrors test does not touch) keeps the two tests independent for
// the lifetime of the test binary.
func TestReport_WriteTo_RegisteredRendererIsInvoked(t *testing.T) {
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
