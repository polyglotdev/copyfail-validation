// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import "errors"

// Sentinel errors returned by this package. Callers MUST match with
// errors.Is rather than string comparison — error messages are not part
// of the package's API contract and may change between minor releases.
var (
	// ErrNoPkgManager is returned by Detect when neither the rpm nor the
	// dpkg backend's underlying binary resolves via the internal/exec
	// allowlist. The integrity.su_binary check translates this into a
	// Skip with reason="no supported package manager (rpm, dpkg)" rather
	// than an Error: the absence of a package manager is a property of
	// the host (e.g., minimal container, source-built distro), not a
	// failure of the check itself. See spec §5 State-Semantics table.
	ErrNoPkgManager = errors.New("integrity: no supported package manager (rpm, dpkg) found")

	// ErrPackageUnknown is returned by PkgMgr.OwnerOf when the queried
	// path is not claimed by any installed package. For rpm this surfaces
	// when `rpm -qf` exits non-zero with the "is not owned by any package"
	// stderr; for dpkg it surfaces when `dpkg -S` exits non-zero with the
	// "no path found matching pattern" stderr.
	//
	// Callers SHOULD treat this as a check-specific outcome (the file is
	// manually placed, or installed by a tool the package manager did
	// not see) rather than a backend failure. Using a sentinel lets
	// callers distinguish this case from a generic exec error via
	// errors.Is — without it the check would either swallow the
	// distinction or have to string-match subprocess stderr.
	ErrPackageUnknown = errors.New("integrity: file not owned by any installed package")
)
