// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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

// hasErrorAt reports whether an error at or under path contains substr.
func hasErrorAt(result validate.Result, path, substr string) bool {
	for _, d := range result.Errors {
		if strings.HasPrefix(d.Path, path) && strings.Contains(d.Message, substr) {
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

func TestValidate_RejectsWeakSignaturesAndDigests(t *testing.T) {
	result := validate.Validate(parse(t, fixture.WeakSignatureJSON))

	if result.IsValid {
		t.Fatal("expected invalid catalog, got IsValid=true")
	}

	if result.ConformanceLevel == validate.Trusted {
		t.Errorf("level = %v, want not Trusted", result.ConformanceLevel)
	}

	const manifest = "catalog.entries[%d].trustManifest"

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			"catalog signature HMAC", "catalog.signature",
			"signature algorithm 'HS256' must be rejected",
		},
		{
			"entry manifest HMAC", fmt.Sprintf(manifest, 0) + ".signature",
			"signature algorithm 'HS256' must be rejected",
		},
		{
			"entry manifest alg none", fmt.Sprintf(manifest, 1) + ".signature",
			"signature algorithm 'none' must be rejected",
		},
		{
			"subject md5 digest", fmt.Sprintf(manifest, 1) + ".subject.digest",
			`digest algorithm is weaker than SHA-256: "md5"`,
		},
		{
			"alg none is case-insensitive", fmt.Sprintf(manifest, 2) + ".signature",
			"signature algorithm 'nOnE' must be rejected",
		},
		{
			"undecodable header is an error, not skipped", fmt.Sprintf(manifest, 3) + ".signature",
			"declaring an 'alg'",
		},
		{
			"attestation md5 digest", fmt.Sprintf(manifest, 4) + ".attestations[0].digest",
			`digest algorithm is weaker than SHA-256: "md5"`,
		},
		{
			"provenance sha1 sourceDigest", fmt.Sprintf(manifest, 4) + ".provenance[0].sourceDigest",
			`digest algorithm is weaker than SHA-256: "sha1"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !hasErrorAt(result, tc.path, tc.want) {
				t.Errorf("want error at %s containing %q, got: %+v", tc.path, tc.want, result.Errors)
			}
		})
	}

	t.Run("compliant entry is clean", func(t *testing.T) {
		path := fmt.Sprintf(manifest, 5)

		if hasErrorAt(result, path, "") {
			t.Errorf("expected no errors under %s, got: %+v", path, result.Errors)
		}
	})
}

func TestValidate_SignatureMessageDoesNotMentionTrustManifest(t *testing.T) {
	// The check runs on the catalog's own signature too, which is not a trust
	// manifest.
	result := validate.Validate(parse(t, fixture.WeakSignatureJSON))

	for _, d := range result.Errors {
		if d.Path == "catalog.signature" && strings.Contains(d.Message, "trust manifest") {
			t.Errorf("a catalog signature is not a trust manifest, got: %q", d.Message)
		}
	}
}

func TestValidate_WeakAlgorithmOrDigestIsNotTrusted(t *testing.T) {
	const (
		noneSignature = "eyJhbGciOiJub25lIn0..c2ln"
		hmacSignature = "eyJhbGciOiJIUzI1NiJ9..c2ln"
		md5Digest     = "md5:0123456789abcdef0123456789abcdef"
		sha1Digest    = "sha1:0123456789abcdef0123456789abcdef01234567"
	)

	tests := []struct {
		name   string
		mutate func(c *catalog.AICatalog)
	}{
		{"alg none on an entry manifest", func(c *catalog.AICatalog) {
			c.Entries[0].TrustManifest.Signature = noneSignature
		}},
		{"HMAC on the catalog signature", func(c *catalog.AICatalog) {
			c.Signature = hmacSignature
		}},
		{"md5 subject digest", func(c *catalog.AICatalog) {
			c.Entries[0].TrustManifest.Subject.Digest = md5Digest
		}},
		{"md5 attestation digest", func(c *catalog.AICatalog) {
			c.Entries[0].TrustManifest.Attestations[0].Digest = md5Digest
		}},
		{"sha1 provenance sourceDigest", func(c *catalog.AICatalog) {
			c.Entries[0].TrustManifest.Provenance[0].SourceDigest = sha1Digest
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := parse(t, fixture.TrustCleanJSON)

			if got := validate.Validate(c); !got.IsValid || got.ConformanceLevel != validate.Trusted {
				t.Fatalf("baseline must be a valid Trusted catalog, got valid=%v level=%v errors=%+v",
					got.IsValid, got.ConformanceLevel, got.Errors)
			}

			tc.mutate(c)

			result := validate.Validate(c)

			if result.IsValid {
				t.Error("expected invalid catalog, got IsValid=true")
			}

			if result.ConformanceLevel == validate.Trusted {
				t.Errorf("level = %v, want not Trusted", result.ConformanceLevel)
			}
		})
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
		`subject.identifier "urn:other" must equal the entry identifier "urn:mismatched-subject"`,
		`subject.version "9.9.9" must equal the entry version ""`,
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

// diagnostic is a code and path, compared as a set.
type diagnostic struct {
	Code validate.Code
	Path string
}

func codes(diagnostics []validate.Diagnostic) []diagnostic {
	got := make([]diagnostic, 0, len(diagnostics))

	for _, d := range diagnostics {
		got = append(got, diagnostic{d.Code, d.Path})
	}

	return got
}

func TestValidate_DidWebProfile(t *testing.T) {
	const entry = "catalog.entries[%d].trustManifest"

	result := validate.Validate(parse(t, fixture.ProfileJSON))

	wantWarnings := []diagnostic{
		{validate.CodeProfileIdentifier, fmt.Sprintf(entry, 1)},
		{validate.CodeProfileIdentity, fmt.Sprintf(entry, 2) + ".identity"},
		{validate.CodeProfileIdentity, fmt.Sprintf(entry, 3) + ".identity"},
		{validate.CodeProfileType, fmt.Sprintf(entry, 4) + ".identityType"},
		{validate.CodeProfileAlgorithm, fmt.Sprintf(entry, 5) + ".signature"},
		{validate.CodeProfileKeyID, fmt.Sprintf(entry, 6) + ".signature"},
		{validate.CodeProfileKeyID, fmt.Sprintf(entry, 7) + ".signature"},
		{validate.CodeProfileKeyID, fmt.Sprintf(entry, 8) + ".signature"},
		{validate.CodeProfileHeader, fmt.Sprintf(entry, 9) + ".signature"},
		{validate.CodeProfileIdentifier, fmt.Sprintf(entry, 10)},
	}

	wantErrors := []diagnostic{
		{validate.CodeSignatureB64, fmt.Sprintf(entry, 11) + ".signature"},
		{validate.CodeSignatureMalformed, fmt.Sprintf(entry, 12) + ".signature"},
		{validate.CodeSignatureForm, fmt.Sprintf(entry, 13) + ".signature"},
	}

	if got := codes(result.Warnings); !sameSet(got, wantWarnings) {
		t.Errorf("warnings = %v, want %v", got, wantWarnings)
	}

	if got := codes(result.Errors); !sameSet(got, wantErrors) {
		t.Errorf("errors = %v, want %v", got, wantErrors)
	}

	if result.ConformanceLevel == validate.Trusted {
		t.Error("a catalog with profile violations must not be Trusted")
	}
}

func sameSet(got, want []diagnostic) bool {
	if len(got) != len(want) {
		return false
	}

	for _, d := range want {
		if !slices.Contains(got, d) {
			return false
		}
	}

	return true
}

func TestValidate_ProfileViolationHoldsBackTrusted(t *testing.T) {
	c := parse(t, fixture.TrustCleanJSON)
	c.Entries[0].TrustManifest.Identity = "did:web:other.example"

	result := validate.Validate(c)

	if !result.IsValid {
		t.Fatalf("a profile violation is a warning, got errors: %+v", result.Errors)
	}

	if result.ConformanceLevel != validate.Discoverable {
		t.Errorf("level = %v, want Discoverable", result.ConformanceLevel)
	}
}

func TestValidate_ExpiryFollowsClock(t *testing.T) {
	c := parse(t, fixture.TrustCleanJSON)
	c.Entries[0].TrustManifest.ExpiresAt = "2026-06-01T00:00:00Z"

	at := func(value string) validate.Option {
		now, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatalf("parse clock: %v", err)
		}

		return validate.WithClock(func() time.Time { return now })
	}

	before := validate.Validate(c, at("2026-05-31T00:00:00Z"))
	if before.ConformanceLevel != validate.Trusted || len(before.Warnings) != 0 {
		t.Errorf("before expiry: level=%v warnings=%+v", before.ConformanceLevel, before.Warnings)
	}

	after := validate.Validate(c, at("2026-06-02T00:00:00Z"))

	if !after.IsValid || after.ConformanceLevel != validate.Discoverable {
		t.Errorf("after expiry: valid=%v level=%v", after.IsValid, after.ConformanceLevel)
	}

	want := []diagnostic{{validate.CodeManifestExpired, "catalog.entries[0].trustManifest.expiresAt"}}
	if got := codes(after.Warnings); !sameSet(got, want) {
		t.Errorf("warnings = %v, want %v", got, want)
	}
}

func TestValidate_WithMaxNestingDepth(t *testing.T) {
	c := parse(t, fixture.NestedMaxJSON)

	if result := validate.Validate(c, validate.WithMaxNestingDepth(1)); result.IsValid {
		t.Error("expected a depth error with a limit of 1")
	}

	if result := validate.Validate(c, validate.WithMaxNestingDepth(10)); !result.IsValid {
		t.Errorf("expected nesting within a limit of 10 to be valid, got: %+v", result.Errors)
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
