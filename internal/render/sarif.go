// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/polyglotdev/copyfail-validation/report"
)

// SARIF v2.1.0 schema constants. Frozen at publication; do not bump
// without updating the rendered output across the test suite.
const (
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
)

// driverInformationURI is the canonical project home page that GitHub
// Code Scanning uses to deep-link from a finding back to docs.
const driverInformationURI = "https://github.com/polyglotdev/copyfail-validation"

// sarifLog is the top-level SARIF document, restricted to the fields
// this renderer emits. Field tags drive the wire format; struct order
// is purely cosmetic since json.Marshal serializes in declaration
// order, which (combined with json.Indent) keeps the output stable
// across runs for golden-file pinning.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

// sarifRun is one validator execution. v0.1 always emits exactly one
// run per Report.
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
}

// sarifTool wraps the driver descriptor.
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

// sarifDriver names the validator and lists its rules. The rules
// array is deduplicated by CheckID so each unique check appears once.
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

// sarifRule describes one check definition. v0.1 populates short and
// full descriptions from the Result.Title (the Check.Description text
// is unavailable in the rendering layer — see rendering limitation
// note in the package doc).
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMultiText `json:"shortDescription"`
	FullDescription  sarifMultiText `json:"fullDescription"`
	Help             sarifMultiText `json:"help"`
}

// sarifMultiText is SARIF's multi-format text container. v0.1 only
// uses plain text; the markdown variant is reserved for future use.
type sarifMultiText struct {
	Text string `json:"text"`
}

// sarifResult is one Result. The Level field is omitted via omitempty
// for non-failure kinds where it would be "none" anyway and would
// only add noise to the document.
type sarifResult struct {
	Message sarifMultiText `json:"message"`
	RuleID  string         `json:"ruleId"`
	Kind    string         `json:"kind"`
	Level   string         `json:"level,omitempty"`
}

// sarifInvocation captures execution-time facts. Only the fields the
// validator actually populates are emitted.
type sarifInvocation struct {
	StartTimeUTC        string `json:"startTimeUtc"`
	Machine             string `json:"machine"`
	ExecutionSuccessful bool   `json:"executionSuccessful"`
}

// RenderSARIF writes rep to w as a SARIF v2.1.0 log document and
// returns the byte count actually written.
//
// Mapping:
//   - One sarifRun per call.
//   - sarifResult.kind = report.State.SARIFKind() ("pass", "fail",
//     "notApplicable", or "open").
//   - sarifResult.level = "error" for required failures, "warning"
//     for advisory failures, omitted otherwise (SARIF default "none").
//   - sarifRule entries are deduplicated by report.Result.CheckID, so
//     a check that produced multiple Results contributes one rule.
//   - sarifInvocation.executionSuccessful = true iff there are no
//     required failures and no required errors (matches the CLI exit
//     code contract in spec §6).
//   - sarifInvocation.startTimeUtc = rep.Generated formatted as
//     RFC3339 in UTC. sarifInvocation.machine = rep.Host.Hostname.
//
// Output is pretty-printed with a two-space indent (matches the JSON
// renderer) and ends with a trailing newline.
//
//nolint:revive // Render* prefix is the documented contract; see RenderJSON.
func RenderSARIF(w io.Writer, rep report.Report) (int64, error) {
	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           rep.Tool.Name,
						Version:        rep.Tool.Version,
						InformationURI: driverInformationURI,
						Rules:          buildSARIFRules(rep.Results),
					},
				},
				Results:     buildSARIFResults(rep.Results),
				Invocations: []sarifInvocation{buildSARIFInvocation(rep)},
			},
		},
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEncode, err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", jsonIndent); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrEncode, err)
	}
	out.WriteByte('\n')
	return flushAll(w, out.Bytes())
}

// buildSARIFRules returns the deduplicated rule descriptors for the
// Results slice. Order is stable: rules are sorted by CheckID so the
// document is byte-identical across runs given the same Results.
func buildSARIFRules(results []report.Result) []sarifRule {
	seen := make(map[string]report.Result, len(results))
	for _, r := range results {
		// First occurrence wins — checks should be idempotent in
		// Title so this rarely matters, but pinning "first wins"
		// keeps the output stable when callers do retry a check.
		if _, ok := seen[r.CheckID]; !ok {
			seen[r.CheckID] = r
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		r := seen[id]
		rules = append(rules, sarifRule{
			ID:               r.CheckID,
			Name:             r.Title,
			ShortDescription: sarifMultiText{Text: r.Title},
			FullDescription:  sarifMultiText{Text: r.Title},
			Help:             sarifMultiText{Text: r.Title},
		})
	}
	return rules
}

// buildSARIFResults converts each report.Result into the SARIF
// equivalent. The translation is 1:1 — order and count match the
// input — so callers can correlate Results across formats by index.
func buildSARIFResults(results []report.Result) []sarifResult {
	out := make([]sarifResult, 0, len(results))
	for _, r := range results {
		out = append(out, sarifResult{
			RuleID:  r.CheckID,
			Kind:    r.State.SARIFKind(),
			Level:   sarifLevel(r),
			Message: sarifMultiText{Text: sarifMessage(r)},
		})
	}
	return out
}

// sarifLevel maps a Result onto the SARIF level enum. Per the spec:
// "error" for failures of required checks, "warning" for failures of
// advisory checks, "" (which json.Marshal omits) otherwise.
func sarifLevel(r report.Result) string {
	if r.State != report.StateFail {
		return ""
	}
	if r.Severity.IsRequired() {
		return "error"
	}
	return "warning"
}

// sarifMessage returns the human-readable description SARIF consumers
// (e.g., GitHub Code Scanning) display next to the rule ID. The
// detail field is preferred; on errors the wrapped Err message is
// substituted; on a clean pass we fall back to the title.
func sarifMessage(r report.Result) string {
	if r.State == report.StateError && r.Err != "" {
		return r.Err
	}
	if r.Detail != "" {
		return r.Detail
	}
	return r.Title
}

// buildSARIFInvocation captures execution-time facts about the run.
// executionSuccessful follows the spec §6 exit-code contract: a run
// is "successful" iff no required check failed or errored. Advisory
// failures are reported but do NOT flip the flag.
func buildSARIFInvocation(rep report.Report) sarifInvocation {
	return sarifInvocation{
		ExecutionSuccessful: rep.Summary.Required.Fail == 0 && rep.Summary.Required.Error == 0,
		StartTimeUTC:        rep.Generated.UTC().Format(time.RFC3339),
		Machine:             rep.Host.Hostname,
	}
}
