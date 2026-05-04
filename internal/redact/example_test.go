// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/redact"
)

// ExampleRedact shows the canonical redactor behavior on a few common
// shapes. The keyword from the matched group is preserved in the output
// so an operator reading the redacted line can still see WHICH secret
// was found, just not its value.
func ExampleRedact() {
	for _, in := range []string{
		"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
		"password: hunter2",
		"Reset your password from the portal", // unchanged: no separator
	} {
		fmt.Println(redact.Redact(in))
	}
	// Output:
	// aws_access_key_id=***REDACTED***
	// Authorization=***REDACTED***
	// password=***REDACTED***
	// Reset your password from the portal
}

// ExampleRedact_multiline shows that redaction is line-bounded: each
// affected line is replaced independently, leaving non-secret lines
// (including those with secret-like words in prose) untouched.
func ExampleRedact_multiline() {
	in := `command: modprobe -nv algif_aead
password=hunter2
result: ok`
	fmt.Println(redact.Redact(in))
	// Output:
	// command: modprobe -nv algif_aead
	// password=***REDACTED***
	// result: ok
}
