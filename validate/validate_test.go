// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
	"github.com/Agent-Card/ai-catalog-go/validate"
)

// diagnostic is the part of a validate.Diagnostic the tests assert on.
type diagnostic struct {
	Code validate.Code
	Path string
}

func parse(t *testing.T, name string) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.Parse(fixture.Read(t, name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	return c
}

// compare checks that got holds exactly the diagnostics in want, in any order,
// each with a message.
func compare(t *testing.T, kind string, got []validate.Diagnostic, want []diagnostic) {
	t.Helper()

	found := make([]diagnostic, 0, len(got))

	for _, d := range got {
		if d.Message == "" {
			t.Errorf("%s %s at %s has no message", kind, d.Code, d.Path)
		}

		found = append(found, diagnostic{d.Code, d.Path})
	}

	less := func(a, b diagnostic) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Code, b.Code))
	}

	slices.SortFunc(found, less)

	want = slices.Clone(want)
	slices.SortFunc(want, less)

	if !slices.Equal(found, want) {
		t.Errorf("%ss:\n got %v\nwant %v", kind, found, want)
	}
}

func entry(i int, member string) string {
	return fmt.Sprintf("catalog.entries[%d]%s", i, member)
}

func TestValidate_Levels(t *testing.T) {
	tests := []struct {
		fixture string
		valid   bool
		level   validate.ConformanceLevel
	}{
		{"minimal.json", true, validate.Minimal},
		{"discoverable.json", true, validate.Discoverable},
		{"unsigned_trust.json", true, validate.Discoverable},
		{"trust_clean.json", true, validate.Trusted},
		{"catalog.json", true, validate.Trusted},
		{"weak_signature.json", false, validate.Minimal},
	}

	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			result := validate.Validate(parse(t, tc.fixture))

			if result.IsValid != tc.valid || result.ConformanceLevel != tc.level {
				t.Errorf("valid=%t level=%v, want valid=%t level=%v (errors %+v)",
					result.IsValid, result.ConformanceLevel, tc.valid, tc.level, result.Errors)
			}
		})
	}
}

func TestValidate_Rules(t *testing.T) {
	result := validate.Validate(parse(t, "invalid.json"))

	wantErrors := []diagnostic{
		{validate.CodeHostMember, "catalog.host.displayName"},
		{validate.CodeSignatureForm, "catalog.signature"},
		{validate.CodeExtensionKey, "catalog.extensions"},
		{validate.CodeEntryArtifact, entry(0, "")},
		{validate.CodeEntryArtifact, entry(1, "")},
		{validate.CodeEntryDuplicate, entry(3, "")},
		{validate.CodeEntryDuplicate, entry(5, "")},
		{validate.CodeEntryVersion, entry(7, ".identifier")},
		{validate.CodeManifestEmpty, entry(8, ".trustManifest")},
		{validate.CodeEntryMember, entry(9, ".identifier")},
		{validate.CodeEntryMember, entry(9, ".type")},
		{validate.CodePublisherMember, entry(9, ".publisher.identifier")},
		{validate.CodePublisherMember, entry(9, ".publisher.displayName")},
		{validate.CodeManifestIdentity, entry(9, ".trustManifest.identity")},
		{validate.CodeManifestEmpty, entry(9, ".trustManifest")},
		{validate.CodeTimestamp, entry(10, ".updatedAt")},
		{validate.CodeExtensionKey, entry(11, ".extensions")},
		{validate.CodeExtensionKey, entry(11, ".trustManifest.extensions")},
		{validate.CodeManifestEmpty, entry(12, ".trustManifest")},
		{validate.CodeManifestEmpty, entry(13, ".trustManifest")},
		{validate.CodeManifestSignedMember, entry(13, ".trustManifest.subject")},
		{validate.CodeManifestSignedMember, entry(13, ".trustManifest.issuedAt")},
		{validate.CodeTimestamp, entry(14, ".trustManifest.issuedAt")},
		{validate.CodeSubjectMismatch, entry(15, ".trustManifest.subject.identifier")},
		{validate.CodeSubjectMismatch, entry(15, ".trustManifest.subject.version")},
		{validate.CodeSubjectMismatch, entry(15, ".trustManifest.subject.type")},
		{validate.CodeSubjectMismatch, entry(15, ".trustManifest.subject.url")},
		{validate.CodeNestedInvalid, entry(16, ".data")},
	}

	wantWarnings := []diagnostic{
		{validate.CodeIdentifierNotURI, entry(10, ".identifier")},
		{validate.CodeManifestExpired, entry(14, ".trustManifest.expiresAt")},
		{validate.CodeProfileIdentifier, entry(15, ".trustManifest")},
		{validate.CodeProfileKeyID, entry(15, ".trustManifest.signature")},
	}

	compare(t, "error", result.Errors, wantErrors)
	compare(t, "warning", result.Warnings, wantWarnings)
}

func TestValidate_WeakSignaturesAndDigests(t *testing.T) {
	result := validate.Validate(parse(t, "weak_signature.json"))

	want := []diagnostic{
		{validate.CodeSignatureAlgorithm, "catalog.signature"},
		{validate.CodeSignatureAlgorithm, entry(0, ".trustManifest.signature")},
		{validate.CodeSignatureAlgorithm, entry(1, ".trustManifest.signature")},
		{validate.CodeDigestInvalid, entry(1, ".trustManifest.subject.digest")},
		{validate.CodeSignatureAlgorithm, entry(2, ".trustManifest.signature")},
		{validate.CodeSignatureMalformed, entry(3, ".trustManifest.signature")},
		{validate.CodeDigestInvalid, entry(4, ".trustManifest.attestations[0].digest")},
		{validate.CodeDigestInvalid, entry(4, ".trustManifest.provenance[0].sourceDigest")},
	}

	compare(t, "error", result.Errors, want)
}

func TestValidate_DidWebProfile(t *testing.T) {
	result := validate.Validate(parse(t, "profile.json"))

	trustManifest := func(i int, member string) string { return entry(i, ".trustManifest"+member) }

	wantWarnings := []diagnostic{
		{validate.CodeProfileIdentifier, trustManifest(1, "")},
		{validate.CodeProfileIdentity, trustManifest(2, ".identity")},
		{validate.CodeProfileIdentity, trustManifest(3, ".identity")},
		{validate.CodeProfileType, trustManifest(4, ".identityType")},
		{validate.CodeProfileAlgorithm, trustManifest(5, ".signature")},
		{validate.CodeProfileKeyID, trustManifest(6, ".signature")},
		{validate.CodeProfileKeyID, trustManifest(7, ".signature")},
		{validate.CodeProfileKeyID, trustManifest(8, ".signature")},
		{validate.CodeProfileHeader, trustManifest(9, ".signature")},
		{validate.CodeProfileIdentifier, trustManifest(10, "")},
		{validate.CodeProfileIdentifier, trustManifest(14, "")},
		{validate.CodeProfileIdentifier, trustManifest(15, "")},
	}

	wantErrors := []diagnostic{
		{validate.CodeSignatureB64, trustManifest(11, ".signature")},
		{validate.CodeSignatureMalformed, trustManifest(12, ".signature")},
		{validate.CodeSignatureForm, trustManifest(13, ".signature")},
	}

	compare(t, "warning", result.Warnings, wantWarnings)
	compare(t, "error", result.Errors, wantErrors)
}

// A profile violation is a warning: the catalog stays valid but is not Trusted.
func TestValidate_ProfileViolationHoldsBackTrusted(t *testing.T) {
	c := parse(t, "trust_clean.json")
	c.Entries[0].TrustManifest.Identity = "did:web:other.example"

	result := validate.Validate(c)

	if !result.IsValid || result.ConformanceLevel != validate.Discoverable {
		t.Errorf("valid=%t level=%v, want a valid Discoverable catalog", result.IsValid, result.ConformanceLevel)
	}
}

func TestValidate_ExpiryFollowsClock(t *testing.T) {
	c := parse(t, "trust_clean.json")
	c.Entries[0].TrustManifest.ExpiresAt = "2026-06-01T00:00:00Z"

	clock := func(value string) validate.Option {
		now, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatalf("parse clock: %v", err)
		}

		return validate.WithClock(func() time.Time { return now })
	}

	before := validate.Validate(c, clock("2026-05-31T00:00:00Z"))
	if before.ConformanceLevel != validate.Trusted || len(before.Warnings) != 0 {
		t.Errorf("before expiry: level=%v warnings=%+v", before.ConformanceLevel, before.Warnings)
	}

	after := validate.Validate(c, clock("2026-06-02T00:00:00Z"))
	if !after.IsValid || after.ConformanceLevel != validate.Discoverable {
		t.Errorf("after expiry: valid=%t level=%v", after.IsValid, after.ConformanceLevel)
	}

	compare(t, "warning", after.Warnings,
		[]diagnostic{{validate.CodeManifestExpired, entry(0, ".trustManifest.expiresAt")}})
}

func TestValidate_NestingDepth(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		opts    []validate.Option
		valid   bool
	}{
		{"at the default limit", "nested_max.json", nil, true},
		{"beyond the default limit", "nested_deep.json", nil, false},
		{"beyond a lower limit", "nested_max.json", []validate.Option{validate.WithMaxNestingDepth(1)}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := validate.Validate(parse(t, tc.fixture), tc.opts...)

			if result.IsValid != tc.valid {
				t.Errorf("valid = %t, want %t (errors %+v)", result.IsValid, tc.valid, result.Errors)
			}

			if !tc.valid && !slices.ContainsFunc(result.Errors, func(d validate.Diagnostic) bool {
				return d.Code == validate.CodeNestedDepth
			}) {
				t.Errorf("expected a %s error, got %+v", validate.CodeNestedDepth, result.Errors)
			}
		})
	}
}

func TestValidate_SpecVersion(t *testing.T) {
	tests := map[string]bool{
		"1.0":      true,
		"1.7":      true,
		"":         false,
		"1":        false,
		"one.zero": false,
		"-1.0":     false,
		"2.0":      false,
	}

	for version, valid := range tests {
		result := validate.Validate(&catalog.AICatalog{SpecVersion: version})

		if result.IsValid != valid {
			t.Errorf("specVersion %q: valid = %t, want %t", version, result.IsValid, valid)
		}
	}
}

type stubSource struct {
	doc *catalog.AICatalog
	err error
}

func (s stubSource) Load(context.Context) (*catalog.AICatalog, error) { return s.doc, s.err }

func TestSource(t *testing.T) {
	result, err := validate.Source(context.Background(), stubSource{doc: parse(t, "catalog.json")})
	if err != nil || result.ConformanceLevel != validate.Trusted {
		t.Errorf("level=%v err=%v, want Trusted", result.ConformanceLevel, err)
	}

	if _, err := validate.Source(context.Background(), stubSource{err: errors.New("unavailable")}); err == nil {
		t.Error("expected the load error to propagate")
	}
}
