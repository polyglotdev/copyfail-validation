// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrMalformed is returned by ParseProcModules when a line cannot be
// parsed. The returned error wraps the line number (1-indexed) and the
// offending raw text so operators can identify which line is bad. Match
// with errors.Is — the error message is not part of the package contract
// and may change between minor releases.
var ErrMalformed = errors.New("kernelmod: malformed /proc/modules line")

// procModulesMinFields is the minimum number of whitespace-separated
// columns a /proc/modules row must have. The kernel writes six
// (name, size, refcount, usedby, state, address); we require at least
// the first five. The address is captured by the kernel format but
// deliberately discarded by the parser (see LoadedModule docs).
const procModulesMinFields = 5

// LoadedModule is one row of /proc/modules.
//
// The kernel writes one line per loaded module in the format:
//
//	name size refcount usedby_csv state address
//
// where:
//   - name      is the module name (no spaces; kernel module names are
//     a strict subset of [A-Za-z0-9_]).
//   - size      is the module's in-memory footprint in bytes.
//   - refcount  is the number of users of the module (kernel-internal
//     reference count; not the same as len(UsedBy)).
//   - usedby    is "-" for "no users" or a comma-separated list of
//     dependent module names with no spaces.
//   - state     is one of "Live", "Loading", or "Unloading".
//   - address   is a kernel-space load address; deliberately discarded
//     by the parser because it is per-boot KASLR-randomized noise that
//     leaks host-specific memory layout if surfaced to audit logs.
//
// Field order is laid out for govet's fieldalignment pass (string and
// slice headers first, fixed-width integers last) — the wire-format
// column order is name, size, refcount, usedby, state but that is not
// the in-memory order.
type LoadedModule struct {
	// Name is the kernel module name as reported by /proc/modules
	// (e.g., "algif_aead"). Comparison is case-sensitive.
	Name string

	// State is one of "Live", "Loading", or "Unloading". The parser
	// does not validate against this allowlist (forward-compat with
	// future kernel state names); callers that care should compare to
	// the literal expected value.
	State string

	// UsedBy is the list of dependent module names parsed from the
	// usedby column. The empty case is the empty slice (`[]string{}`),
	// NOT nil — callers iterating without a length check observe a
	// stable shape regardless of whether dependents exist.
	UsedBy []string

	// Size is the module's in-memory footprint in bytes.
	Size int64

	// RefCount is the kernel-internal reference count. This may differ
	// from len(UsedBy): a module with refcount 1 and usedby "-" is held
	// by something the kernel does not name in /proc/modules (typically
	// a bind mount or filesystem in use).
	RefCount int
}

// ParseProcModules parses the contents of /proc/modules from r.
//
// Empty lines (lines that contain nothing but whitespace) are skipped.
// On the first malformed line the parser aborts and returns the
// LoadedModules parsed so far PLUS a wrapped ErrMalformed that includes
// the 1-indexed line number and the raw line text. This aborts-on-bad
// behavior is deliberate: /proc/modules is kernel-generated, so a
// malformed line indicates either a kernel ABI change we have not
// caught up to or a fixture mismatch — both are conditions the caller
// must surface, not silently skip.
//
// A line is malformed if it has fewer than five whitespace-separated
// columns or if size/refcount cannot be parsed as integers. The trailing
// address column is permitted (kernel writes it) but not required.
//
// The returned slice is never nil: empty input yields an empty slice
// with a nil error. Callers can range over the result without a
// nil-check.
func ParseProcModules(r io.Reader) ([]LoadedModule, error) {
	mods := make([]LoadedModule, 0)
	scanner := bufio.NewScanner(r)

	// /proc/modules lines are short (a few hundred bytes); the default
	// 64KiB scanner buffer is plenty. We do not raise it because doing
	// so would invite OOM if a hostile io.Reader streams an
	// arbitrarily long single "line" — bufio.Scanner caps at MaxScanTokenSize
	// by default, returning bufio.ErrTooLong, which we surface as a
	// scanner.Err() below.

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		mod, err := parseProcModulesLine(trimmed)
		if err != nil {
			return mods, fmt.Errorf("%w: line %d: %q: %w", ErrMalformed, lineNum, raw, err)
		}
		mods = append(mods, mod)
	}

	if err := scanner.Err(); err != nil {
		return mods, fmt.Errorf("kernelmod: read /proc/modules: %w", err)
	}

	return mods, nil
}

// parseProcModulesLine parses one trimmed, non-empty line into a
// LoadedModule. Returns a non-nil error if the field count is too low
// or if size/refcount fail to parse as integers. The caller is
// responsible for skipping blank lines and tracking line numbers.
func parseProcModulesLine(line string) (LoadedModule, error) {
	// strings.Fields handles arbitrary runs of whitespace, which
	// matches what the kernel emits (single spaces between columns,
	// no tabs in practice but tolerant if a future kernel adds them).
	fields := strings.Fields(line)
	if len(fields) < procModulesMinFields {
		return LoadedModule{}, fmt.Errorf("expected at least %d fields, got %d", procModulesMinFields, len(fields))
	}

	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return LoadedModule{}, fmt.Errorf("size field %q is not an integer: %w", fields[1], err)
	}
	if size < 0 {
		return LoadedModule{}, fmt.Errorf("size field %q is negative", fields[1])
	}

	refCount, err := strconv.Atoi(fields[2])
	if err != nil {
		return LoadedModule{}, fmt.Errorf("refcount field %q is not an integer: %w", fields[2], err)
	}
	if refCount < 0 {
		return LoadedModule{}, fmt.Errorf("refcount field %q is negative", fields[2])
	}

	usedBy := parseUsedBy(fields[3])

	return LoadedModule{
		Name:     fields[0],
		Size:     size,
		RefCount: refCount,
		UsedBy:   usedBy,
		State:    fields[4],
	}, nil
}

// parseUsedBy converts the raw usedby column into a dependent-name slice.
// The kernel writes "-" when a module has no users and a comma-separated
// list otherwise. Trailing commas in the kernel format are not expected
// but are tolerated (filtered out as empty entries) so a future kernel
// quirk does not turn into a parse error.
//
// Returns []string{} (NOT nil) for the no-users case so callers can
// iterate without a length check.
func parseUsedBy(field string) []string {
	if field == "-" || field == "" {
		return []string{}
	}
	parts := strings.Split(field, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// IsLoaded reports whether modules contains an entry whose Name equals
// name. The comparison is case-sensitive — kernel module names are
// case-sensitive (the kernel rejects `ALGIF_AEAD` as a load target for
// `algif_aead`), so callers passing a user-supplied module name should
// not lower-case it before lookup.
//
// Returns false for an empty modules slice and for a name that matches
// no entry. There is no error path: an absent module is a valid query
// result, not an exceptional condition.
func IsLoaded(modules []LoadedModule, name string) bool {
	for _, m := range modules {
		if m.Name == name {
			return true
		}
	}
	return false
}
