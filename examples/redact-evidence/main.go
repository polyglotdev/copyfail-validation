// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Command redact-evidence demonstrates the redact package on a small
// fixture that mimics the kind of evidence string a check might emit.
// Useful as a sanity check that the redactor still scrubs the patterns
// you care about — and as a place to test new patterns before opening
// a PR to extend RedactionPattern.
//
// Run with: go run ./examples/redact-evidence
package main

import (
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/redact"
)

const sample = `command: aws sts get-caller-identity
env:
  AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  AWS_SESSION_TOKEN=FwoGZXIvYXdzEPv//////////wEaDExample==
http_request:
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature
  Content-Type: application/json
notes:
  Reset your password from the portal if needed.
  See the API key documentation at https://example.com/docs/api-keys`

func main() {
	fmt.Println("--- before redaction ---")
	fmt.Println(sample)
	fmt.Println()
	fmt.Println("--- after redaction ---")
	fmt.Println(redact.Redact(sample))
}
