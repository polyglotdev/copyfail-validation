// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package canonjson_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/canonjson"
)

func TestCanonicalize_SortsKeys(t *testing.T) {
	t.Parallel()
	in := []byte(`{"b":1,"a":2,"c":{"y":3,"x":4}}`)
	got, err := canonjson.Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1,"c":{"x":4,"y":3}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalize_StripsWhitespace(t *testing.T) {
	t.Parallel()
	in := []byte("{\n  \"a\": 1,\n  \"b\": 2\n}")
	got, err := canonjson.Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1,"b":2}`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSHA256_Stable(t *testing.T) {
	t.Parallel()
	a := []byte(`{"a":1,"b":2}`)
	b := []byte(`{"b": 2, "a": 1}`)
	ha, err := canonjson.SHA256(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := canonjson.SHA256(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Errorf("equivalent JSON produced different hashes:\n  a: %s\n  b: %s", ha, hb)
	}
	// sanity: length is 64 hex chars
	if len(ha) != 2*sha256.Size {
		t.Errorf("hash length = %d, want %d", len(ha), 2*sha256.Size)
	}
	// sanity: hex-decodable
	if _, err := hex.DecodeString(ha); err != nil {
		t.Errorf("hash not hex: %v", err)
	}
	// (the sample JSON IS valid; this assertion just exercises encoding/json so the
	// import isn't unused if the implementation switches strategies)
	var v any
	if err := json.Unmarshal(a, &v); err != nil {
		t.Fatal(err)
	}
}
