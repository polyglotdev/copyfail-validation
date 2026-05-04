// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/polyglotdev/copyfail-validation/report"
)

// EnvJSONCompact is the env-var name that switches RenderJSON from
// the default two-space indented form to a compact single-line form
// (one line of JSON plus a trailing newline) when set to "1". Used
// by log shippers and pipelines that want one document per line.
const EnvJSONCompact = "COPYFAIL_JSON_COMPACT"

// jsonIndent is the indent string used by the pretty-print mode. Two
// spaces matches gofmt and is the convention across the spec
// (deliberately not four).
const jsonIndent = "  "

// RenderJSON writes rep to w as a JSON document and returns the byte
// count actually written.
//
// By default the document is pretty-printed with a two-space indent
// and a trailing newline (operators read it). When the environment
// variable named by EnvJSONCompact is set to "1", the document is
// emitted on a single line followed by a trailing newline (small for
// log shipping; one document per line).
//
// Errors are wrapped with ErrEncode (json.Marshal failure) or ErrRender
// (writer failure). The writer is unchanged on encode failure.
//
// The "Render" prefix is intentional: the four renderer entry points
// share a uniform name so init() can register them by symmetry. The
// stutter against the package name is accepted as a documentation
// affordance, not an oversight.
//
//nolint:revive // Render* prefix is the documented contract; see godoc above.
func RenderJSON(w io.Writer, rep report.Report) (int64, error) {
	raw, err := json.Marshal(rep)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEncode, err)
	}

	var out bytes.Buffer
	if os.Getenv(EnvJSONCompact) == "1" {
		// json.Marshal already emits compact output; just copy it.
		out.Write(raw)
	} else {
		if err := json.Indent(&out, raw, "", jsonIndent); err != nil {
			return 0, fmt.Errorf("%w: %w", ErrEncode, err)
		}
	}
	out.WriteByte('\n')

	return flushAll(w, out.Bytes())
}
