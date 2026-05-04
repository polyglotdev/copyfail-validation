// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package canonjson_test

import (
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/canonjson"
)

// ExampleCanonicalize shows how the package transforms JSON into the
// canonical form used by Report.WriteTo when --sign is set: sorted
// keys at every level, no insignificant whitespace, integer values
// preserved as integers (not coerced through float64).
func ExampleCanonicalize() {
	in := []byte(`{"b":{"y":2,"x":1},"a":[3,2,1]}`)
	out, err := canonjson.Canonicalize(in)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(out))
	// Output:
	// {"a":[3,2,1],"b":{"x":1,"y":2}}
}

// ExampleSHA256 shows the canonical use case: two semantically
// identical JSON encodings produce the same digest. This is what makes
// the --sign sidecar reproducible across Go versions and minor encoder
// changes.
func ExampleSHA256() {
	a, _ := canonjson.SHA256([]byte(`{"a":1,"b":2}`))
	b, _ := canonjson.SHA256([]byte("{\n  \"b\": 2,\n  \"a\": 1\n}"))
	fmt.Println(a == b)
	// Output:
	// true
}
