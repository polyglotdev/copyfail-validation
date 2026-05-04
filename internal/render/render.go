// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"errors"
	"fmt"
	"io"
)

// Sentinel errors returned by renderers. All renderer errors wrap one
// of these so callers can switch on the high-level cause via errors.Is
// without parsing message text.
var (
	// ErrRender is the umbrella error every renderer wraps when an
	// operation fails for a reason that is not specifically modeled
	// below. errors.Is(err, ErrRender) returns true for any error
	// originating in this package.
	ErrRender = errors.New("render: renderer failure")

	// ErrEncode is wrapped when JSON encoding (json.Encoder.Encode or
	// json.Indent) fails. In practice this only happens if a Report
	// carries an unmarshalable Evidence value; tests assert the
	// sentinel rather than a specific encoder error type.
	ErrEncode = errors.New("render: encode failed")

	// ErrShortWrite is wrapped when the underlying io.Writer accepts
	// the bytes but reports a short write, or when an intermediate
	// buffer flush returns fewer bytes than requested. The wrapped
	// error is io.ErrShortWrite from the stdlib.
	ErrShortWrite = errors.New("render: short write to writer")

	// ErrAtomicRename is wrapped by WriteTextfileAtomic when the
	// final os.Rename step fails. Callers can match this sentinel to
	// retry the write or escalate to an operator. The temp file is
	// removed before the error is returned.
	ErrAtomicRename = errors.New("render: atomic rename failed")
)

// flushAll writes b to w, returning the bytes-written count and any
// error wrapped with ErrShortWrite/ErrRender so callers can use
// errors.Is. This is the single place every renderer routes its final
// flush through, keeping the wrapping policy consistent.
func flushAll(w io.Writer, b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := w.Write(b)
	if err != nil {
		return int64(n), fmt.Errorf("%w: %w", ErrRender, err)
	}
	if n != len(b) {
		return int64(n), fmt.Errorf("%w: %w", ErrShortWrite, io.ErrShortWrite)
	}
	return int64(n), nil
}
