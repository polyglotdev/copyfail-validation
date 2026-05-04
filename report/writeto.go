// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"fmt"
	"io"
	"sync"
)

// ErrRendererNotRegistered is returned by Report.WriteTo when no renderer
// has been registered for the requested Format. In production builds the
// internal/render package's init() registers all four renderers; tests
// that import only "report" will hit this error.
var ErrRendererNotRegistered = errors.New("no renderer registered for format")

// Renderer writes a Report to w in some format. Registered via Register.
type Renderer func(w io.Writer, rep Report) (int64, error)

var (
	rendererMu sync.RWMutex
	renderers  = map[Format]Renderer{}
)

// Register installs r as the renderer for f. Subsequent calls with the
// same f overwrite the previous renderer (intended for tests; production
// callers should register exactly once via package init).
//
// Tests that need to install a temporary renderer should pair Register
// with a deferred call to a snapshot-and-restore helper rather than
// leaving the registry mutated for the rest of the test binary. See
// SnapshotRenderers / RestoreRenderers below.
func Register(f Format, r Renderer) {
	rendererMu.Lock()
	defer rendererMu.Unlock()
	renderers[f] = r
}

// SnapshotRenderers returns a shallow copy of the current renderer
// registry. Intended for tests that need to register a temporary
// renderer and restore the prior state on cleanup. The returned map
// is safe for the caller to modify; it does not share storage with
// the live registry.
//
// Typical usage:
//
//	prev := report.SnapshotRenderers()
//	t.Cleanup(func() { report.RestoreRenderers(prev) })
//	report.Register(report.FormatPrometheus, myStubRenderer)
//
// Without snapshot/restore, a test that calls Register leaves the
// registry mutated for the rest of the test binary's lifetime, which
// silently affects every subsequent test that depends on a real
// renderer (e.g., Phase 4's internal/render integration tests).
func SnapshotRenderers() map[Format]Renderer {
	rendererMu.RLock()
	defer rendererMu.RUnlock()
	out := make(map[Format]Renderer, len(renderers))
	for k, v := range renderers {
		out[k] = v
	}
	return out
}

// RestoreRenderers replaces the registry with a snapshot previously
// returned by SnapshotRenderers. Intended for use in t.Cleanup. The
// passed map is shallow-copied; mutating it after Restore does not
// affect the registry.
func RestoreRenderers(snapshot map[Format]Renderer) {
	rendererMu.Lock()
	defer rendererMu.Unlock()
	renderers = make(map[Format]Renderer, len(snapshot))
	for k, v := range snapshot {
		renderers[k] = v
	}
}

// WriteTo writes the Report to w in the given format. Returns the number
// of bytes written and any error from the underlying renderer or writer.
//
// Errors:
//   - ErrUnknownFormat if f is not a recognized Format value.
//   - ErrRendererNotRegistered if f is recognized but no renderer is wired.
//   - Any error returned by the underlying renderer or writer.
func (rep Report) WriteTo(w io.Writer, f Format) (int64, error) {
	switch f {
	case FormatHuman, FormatJSON, FormatSARIF, FormatPrometheus:
		// known format; fall through to renderer lookup
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownFormat, string(f))
	}
	rendererMu.RLock()
	r, ok := renderers[f]
	rendererMu.RUnlock()
	if !ok {
		return 0, fmt.Errorf("%w: %q (did you forget to import internal/render?)", ErrRendererNotRegistered, string(f))
	}
	return r(w, rep)
}
