// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"strings"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
	"github.com/agntcy/ai-catalog-go-sdk/catalog/validate"
)

func mustParse(t *testing.T, doc string) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.ParseString(doc)
	if err != nil {
		t.Fatalf("parse document: %v", err)
	}

	return c
}

func hasError(result validate.Result, substr string) bool {
	for _, d := range result.Errors {
		if strings.Contains(d.Message, substr) {
			return true
		}
	}

	return false
}

func hasWarning(result validate.Result, substr string) bool {
	for _, d := range result.Warnings {
		if strings.Contains(d.Message, substr) {
			return true
		}
	}

	return false
}

func TestValidate_HostlessIsMinimal(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:minimal", "displayName": "Minimal",
			 "type": "application/json", "url": "https://example.com/minimal.json"}
		]
	}`))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Minimal {
		t.Errorf("level = %v, want Minimal", result.ConformanceLevel)
	}
}

func TestValidate_HostIsDiscoverable(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"host": {"displayName": "Example Host"},
		"entries": [
			{"identifier": "urn:example:agent", "displayName": "Agent",
			 "type": "application/json", "url": "https://example.com/agent.json"}
		]
	}`))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Discoverable {
		t.Errorf("level = %v, want Discoverable", result.ConformanceLevel)
	}
}

func TestValidate_TrustManifestIsTrusted(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"host": {"displayName": "Example Host"},
		"entries": [
			{"identifier": "urn:example:trusted", "displayName": "Trusted",
			 "type": "application/json", "url": "https://example.com/trusted.json",
			 "trustManifest": {"identity": "urn:example:trusted"}}
		]
	}`))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Trusted {
		t.Errorf("level = %v, want Trusted", result.ConformanceLevel)
	}
}

func TestValidate_RejectsBothURLAndData(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:test", "displayName": "Test",
			 "type": "application/json", "url": "https://example.com/test.json",
			 "data": {"key": "value"}}
		]
	}`))

	if result.IsValid || !hasError(result, "exactly one of 'url' or 'data'") {
		t.Errorf("expected url/data error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMissingPayload(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:missing", "displayName": "Missing",
			 "type": "application/json"}
		]
	}`))

	if result.IsValid || !hasError(result, "entry must have exactly one of 'url' or 'data'") {
		t.Errorf("expected missing payload error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsDuplicateIdentifier(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:test", "displayName": "First",
			 "type": "application/json", "url": "https://example.com/one.json"},
			{"identifier": "urn:example:test", "displayName": "Second",
			 "type": "application/json", "url": "https://example.com/two.json"}
		]
	}`))

	if result.IsValid || !hasError(result, "duplicate identifier") {
		t.Errorf("expected duplicate identifier error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsDuplicateVersionedPair(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:v", "displayName": "First",
			 "type": "application/json", "url": "https://example.com/one.json", "version": "1.0.0"},
			{"identifier": "urn:example:v", "displayName": "Second",
			 "type": "application/json", "url": "https://example.com/two.json", "version": "1.0.0"}
		]
	}`))

	if result.IsValid || !hasError(result, "duplicate (identifier, version) pair") {
		t.Errorf("expected duplicate pair error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMixedVersioning(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:mixed", "displayName": "Unversioned",
			 "type": "application/json", "url": "https://example.com/u.json"},
			{"identifier": "urn:example:mixed", "displayName": "Versioned",
			 "type": "application/json", "url": "https://example.com/v.json", "version": "1.0.0"}
		]
	}`))

	if result.IsValid || !hasError(result, "cannot appear with and without version") {
		t.Errorf("expected mixed versioning error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMismatchedTrustIdentity(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:test", "displayName": "Test",
			 "type": "application/json", "url": "https://example.com/test.json",
			 "trustManifest": {"identity": "urn:example:other"}}
		]
	}`))

	if result.IsValid || !hasError(result, "does not match entry identifier") {
		t.Errorf("expected trust identity mismatch error, got: %+v", result.Errors)
	}
}

func TestValidate_InvalidUpdatedAtAndNonURIWarning(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "plain-identifier", "displayName": "Plain",
			 "type": "application/json", "url": "https://example.com/plain.json",
			 "updatedAt": "yesterday"}
		]
	}`))

	if !hasError(result, "updatedAt is not a valid RFC 3339 datetime") {
		t.Errorf("expected updatedAt error, got: %+v", result.Errors)
	}

	if !hasWarning(result, "identifier SHOULD be a URN or URI") {
		t.Errorf("expected non-URI warning, got: %+v", result.Warnings)
	}
}

func TestValidate_RejectsEmptyMetadataKeys(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"metadata": {"": true},
		"entries": [
			{"identifier": "urn:example:m", "displayName": "M",
			 "type": "application/json", "url": "https://example.com/m.json",
			 "metadata": {"": 1},
			 "trustManifest": {"identity": "urn:example:m", "metadata": {"": "bad"}}}
		]
	}`))

	count := 0

	for _, d := range result.Errors {
		if strings.Contains(d.Message, "metadata keys must be non-empty strings") {
			count++
		}
	}

	if count != 3 {
		t.Errorf("expected 3 empty-metadata-key errors, got %d: %+v", count, result.Errors)
	}
}

func TestValidate_SpecVersions(t *testing.T) {
	cases := []struct {
		version string
		substr  string
	}{
		{"", "must not be empty"},
		{"1", "Major.Minor format"},
		{"one.zero", "must be non-negative integers"},
		{"2.0", "unsupported specVersion major version"},
	}

	for _, tc := range cases {
		result := validate.Validate(mustParse(t,
			`{"specVersion": "`+tc.version+`", "entries": []}`))

		if !hasError(result, tc.substr) {
			t.Errorf("specVersion %q: expected error %q, got: %+v", tc.version, tc.substr, result.Errors)
		}
	}
}

func TestValidate_NestedCatalog(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:root", "displayName": "Root",
			 "type": "application/ai-catalog+json",
			 "data": {
				"specVersion": "1.0",
				"entries": [
					{"identifier": "urn:example:child", "displayName": "Child",
					 "type": "application/json", "url": "https://example.com/child.json"}
				]
			 }}
		]
	}`))

	if !result.IsValid {
		t.Errorf("expected valid nested catalog, errors: %+v", result.Errors)
	}
}

func TestValidate_InvalidNestedCatalog(t *testing.T) {
	result := validate.Validate(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:bad", "displayName": "Bad",
			 "type": "application/ai-catalog+json",
			 "data": {"specVersion": 12345}}
		]
	}`))

	if result.IsValid || !hasError(result, "nested catalog data is not a valid AI Catalog") {
		t.Errorf("expected invalid nested catalog error, got: %+v", result.Errors)
	}
}

func TestValidate_NestedDepthLimit(t *testing.T) {
	// Build 4 levels of nesting, which exceeds the recommended limit.
	doc := buildNested(4)

	result := validate.Validate(mustParse(t, doc))

	if !hasError(result, "nested catalog depth exceeds recommended limit") {
		t.Errorf("expected depth-limit error, got: %+v", result.Errors)
	}
}

func buildNested(levels int) string {
	if levels == 0 {
		return `{"specVersion": "1.0", "entries": [
			{"identifier": "urn:example:leaf", "displayName": "Leaf",
			 "type": "application/json", "url": "https://example.com/leaf.json"}
		]}`
	}

	return `{"specVersion": "1.0", "entries": [
		{"identifier": "urn:example:nested", "displayName": "Nested",
		 "type": "application/ai-catalog+json", "data": ` + buildNested(levels-1) + `}
	]}`
}

func TestConformanceLevel_String(t *testing.T) {
	cases := map[validate.ConformanceLevel]string{
		validate.Minimal:      "minimal",
		validate.Discoverable: "discoverable",
		validate.Trusted:      "trusted",
	}

	for level, want := range cases {
		if got := level.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", level, got, want)
		}
	}
}
