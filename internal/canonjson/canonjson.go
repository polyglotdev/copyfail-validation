// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package canonjson implements a subset of RFC 8785 (JSON Canonicalization
// Scheme) sufficient for producing reproducible SHA-256 digests of
// validator reports. The full RFC 8785 number-canonicalization rules
// (ECMAScript 6 numeric serialization, exponent normalization) are NOT
// implemented because the Report schema only emits integers and strings —
// no floating-point. If a future schema major adds floats, this package
// must be revisited; a regression test pins the current behavior.
package canonjson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize returns the canonical JSON form of in per the rules above:
// UTF-8, sorted object keys at every level, no insignificant whitespace,
// integers without trailing decimals.
func Canonicalize(in []byte) ([]byte, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.UseNumber() // preserve integer-ness; avoid float64 round-tripping
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonjson: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := write(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SHA256 returns the lowercase-hex SHA-256 digest of Canonicalize(in).
func SHA256(in []byte) (string, error) {
	c, err := Canonicalize(in)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

func write(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(string(x))
	case string:
		b, err := json.Marshal(x) // delegate to stdlib for escape rules per RFC 8259 §7
		if err != nil {
			return fmt.Errorf("canonjson: marshal string: %w", err)
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := write(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // RFC 8785 §3.2.3: sort by code-unit values; ASCII keys → byte-sort works
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("canonjson: marshal key: %w", err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := write(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonjson: unsupported type %T", v)
	}
	return nil
}
