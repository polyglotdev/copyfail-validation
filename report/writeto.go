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
func Register(f Format, r Renderer) {
	rendererMu.Lock()
	defer rendererMu.Unlock()
	renderers[f] = r
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
