// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
	"github.com/Agent-Card/ai-catalog-go/validate"
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

func TestValidate_SignedTrustManifestIsTrusted(t *testing.T) {
	// The comprehensive fixture carries a signed, subject-bound manifest.
	result := validate.Validate(parse(t, fixture.CatalogJSON))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Trusted {
		t.Errorf("level = %v, want Trusted", result.ConformanceLevel)
	}
}

func TestValidate_UnsignedTrustManifestIsOnlyDiscoverable(t *testing.T) {
	// A manifest that is not signed and bound to its artifact cannot reach
	// Trusted.
	result := validate.Validate(parse(t, fixture.UnsignedTrustJSON))

	if !result.IsValid {
		t.Fatalf("expected valid, errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Discoverable {
		t.Errorf("level = %v, want Discoverable", result.ConformanceLevel)
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

func TestValidate_RejectsTrustIdentityWithoutTrustDomain(t *testing.T) {
	result := validate.Validate(parse(t, fixture.UnboundIdentityJSON))

	want := `trustManifest.identity "urn:acme:agent:finance" has no trust domain to align ` +
		`with the entry identifier publisher domain "acme.com"`

	if result.IsValid || !hasError(result, want) {
		t.Errorf("expected unbound trust identity error, got: %+v", result.Errors)
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

func TestValidate_RejectsMalformedExtensionKeys(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	// The fixture carries one bad key on the catalog, one on an entry, and one
	// on a trust manifest.
	wants := []string{`extension key "" must be`, `"not a namespace" must be`, `"nodots" must be`}

	for _, want := range wants {
		if !hasError(result, want) {
			t.Errorf("expected extension key error containing %q, got: %+v", want, result.Errors)
		}
	}
}

func TestValidate_AcceptsURLAndReverseDNSExtensionKeys(t *testing.T) {
	// The comprehensive fixture carries one key of each accepted form.
	result := validate.Validate(parse(t, fixture.CatalogJSON))

	if hasError(result, "extension key") {
		t.Errorf("expected well-formed extension keys to be accepted, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsHollowTrustManifest(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if !hasError(result, "must carry at least one substantive member") {
		t.Errorf("expected hollow trust manifest error, got: %+v", result.Errors)
	}
}

func TestValidate_RejectsSignatureWithoutSubjectAndIssuedAt(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	wants := []string{
		"a trustManifest carrying a signature must include a subject",
		"a trustManifest carrying a signature must include issuedAt",
	}

	for _, want := range wants {
		if !hasError(result, want) {
			t.Errorf("expected error containing %q, got: %+v", want, result.Errors)
		}
	}
}

func TestValidate_RejectsSubjectContradictingItsEntry(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	wants := []string{
		`subject.type "application/gguf" must equal the entry type "application/json"`,
		`subject.url "https://example.com/other.json" must equal the entry url`,
	}

	for _, want := range wants {
		if !hasError(result, want) {
			t.Errorf("expected error containing %q, got: %+v", want, result.Errors)
		}
	}
}

func TestValidate_ManifestTimestamps(t *testing.T) {
	result := validate.Validate(parse(t, fixture.InvalidJSON))

	if !hasError(result, "issuedAt is not a valid RFC 3339 datetime") {
		t.Errorf("expected issuedAt error, got: %+v", result.Errors)
	}

	// An expired manifest is a SHOULD-level rejection, so it warns.
	if !hasWarning(result, "SHOULD be rejected") {
		t.Errorf("expected expiry warning, got: %+v", result.Warnings)
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

func TestValidate_AcceptsNestingAtDepthLimit(t *testing.T) {
	// The limit is the deepest accepted nesting, not the first rejected one.
	result := validate.Validate(parse(t, fixture.NestedMaxJSON))

	if !result.IsValid {
		t.Errorf("expected nesting at the limit to be valid, errors: %+v", result.Errors)
	}
}

// stubSource is a catalog.Source backed by fixture bytes, or by a load failure.
type stubSource struct {
	doc []byte
	err error
}

func (s stubSource) Load(context.Context) (*catalog.AICatalog, error) {
	if s.err != nil {
		return nil, s.err
	}

	doc, err := catalog.Parse(s.doc)
	if err != nil {
		return nil, fmt.Errorf("stub parse: %w", err)
	}

	return doc, nil
}

func TestSource(t *testing.T) {
	result, err := validate.Source(context.Background(), stubSource{doc: fixture.CatalogJSON})
	if err != nil {
		t.Fatalf("Source error: %v", err)
	}

	if !result.IsValid || result.ConformanceLevel != validate.Trusted {
		t.Errorf("unexpected result: valid=%v level=%v errors=%+v",
			result.IsValid, result.ConformanceLevel, result.Errors)
	}
}

func TestSource_LoadFailure(t *testing.T) {
	if _, err := validate.Source(
		context.Background(), stubSource{err: errors.New("backend unavailable")},
	); err == nil {
		t.Fatal("expected a load error to propagate")
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
