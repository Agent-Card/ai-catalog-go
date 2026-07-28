// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"strings"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
	"github.com/agntcy/ai-catalog-go-sdk/internal/fixture"
	"github.com/agntcy/ai-catalog-go-sdk/validate"
)

// parse parses one of the shared fixture documents.
func parse(t *testing.T, data []byte) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.Parse(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	return c
}

// mustParse parses a JSON document supplied inline, for the few tests that
// generate their input programmatically.
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
	result := validate.Validate(parse(t, fixture.MinimalJSON))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Minimal {
		t.Errorf("level = %v, want Minimal", result.ConformanceLevel)
	}
}

func TestValidate_HostIsDiscoverable(t *testing.T) {
	result := validate.Validate(parse(t, fixture.DiscoverableJSON))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Discoverable {
		t.Errorf("level = %v, want Discoverable", result.ConformanceLevel)
	}
}

func TestValidate_TrustManifestIsTrusted(t *testing.T) {
	// The comprehensive fixture carries a trust manifest, so it is Trusted.
	result := validate.Validate(parse(t, fixture.CatalogJSON))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Trusted {
		t.Errorf("level = %v, want Trusted", result.ConformanceLevel)
	}
}

func TestValidate_RejectsBothURLAndData(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "exactly one of 'url' or 'data'") {
		t.Errorf("expected url/data error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMissingPayload(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "entry must have exactly one of 'url' or 'data'") {
		t.Errorf("expected missing payload error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsDuplicateIdentifier(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "duplicate identifier") {
		t.Errorf("expected duplicate identifier error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsDuplicateVersionedPair(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "duplicate (identifier, version) pair") {
		t.Errorf("expected duplicate pair error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMixedVersioning(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "cannot appear with and without version") {
		t.Errorf("expected mixed versioning error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsMisalignedTrustIdentityDomain(t *testing.T) {
	// The invalid fixture pairs publisher domain acme.com with identity domain
	// evil.example.
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "does not align with the entry identifier publisher domain") {
		t.Errorf("expected trust identity domain-alignment error, got: %+v", result.Errors)
	}
}

func TestValidate_AcceptsAlignedNonEqualTrustIdentity(t *testing.T) {
	// The comprehensive fixture binds urn:air:acme.com:... to did:web:acme.com:
	// aligned by domain, not equal to the identifier.
	result := validate.Validate(parse(t, fixture.CatalogJSON))

	if !result.IsValid {
		t.Fatalf("expected valid aligned binding, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Trusted {
		t.Errorf("level = %v, want Trusted", result.ConformanceLevel)
	}
}

func TestValidate_RejectsMissingRequiredFields(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	wants := []string{
		"host.displayName is required",
		"identifier is required and must not be empty",
		"type is required and must not be empty",
		"publisher.identifier is required",
		"publisher.displayName is required",
		"trustManifest.identity is required",
	}

	for _, want := range wants {
		if !hasError(result, want) {
			t.Errorf("expected error containing %q, got: %+v", want, result.Errors)
		}
	}
}

func TestValidate_InvalidUpdatedAtAndNonURIWarning(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if !hasError(result, "updatedAt is not a valid RFC 3339 datetime") {
		t.Errorf("expected updatedAt error, got: %+v", result.Errors)
	}

	if !hasWarning(result, "identifier SHOULD be a URN or URI") {
		t.Errorf("expected non-URI warning, got: %+v", result.Warnings)
	}
}

func TestValidate_RejectsEmptyMetadataKeys(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

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
	// The comprehensive fixture contains a valid nested catalog entry.
	result := validate.Validate(parse(t, fixture.CatalogJSON))

	if !result.IsValid {
		t.Errorf("expected valid nested catalog, errors: %+v", result.Errors)
	}
}

func TestValidate_InvalidNestedCatalog(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if result.IsValid || !hasError(result, "nested catalog data is not a valid AI Catalog") {
		t.Errorf("expected invalid nested catalog error, got: %+v", result.Errors)
	}
}

func TestValidate_NestedDepthLimit(t *testing.T) {
	result := validate.Validate(parse(t, fixture.NestedDeepJSON))

	if !hasError(result, "nested catalog depth exceeds recommended limit") {
		t.Errorf("expected depth-limit error, got: %+v", result.Errors)
	}
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
