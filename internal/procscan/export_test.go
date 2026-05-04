// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package procscan

import "context"

// ScanWithRootForTest exposes the unexported scanWithRoot to the
// external _test package so behavioral tests can build fake /proc
// fixtures under t.TempDir() and exercise the walker without root
// privileges. The function is NOT exported in production builds
// (this file is excluded by the _test.go suffix) — production callers
// must use Scan, which gates on EUID==0 and pins procRoot to "/proc".
func ScanWithRootForTest(ctx context.Context, procRoot string) (ScanResult, error) {
	return scanWithRoot(ctx, procRoot)
}
