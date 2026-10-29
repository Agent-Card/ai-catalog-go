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

const assessorDID = "did:web:assessor.example"

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

func manifest(i int, member string) string {
	return entry(i, ".trustManifests[0]"+member)
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
		{validate.CodeSignatureForm, "catalog.signature.jws"},
		{validate.CodeExtensionKey, "catalog.extensions"},
		{validate.CodeEntryArtifact, entry(0, "")},
		{validate.CodeEntryArtifact, entry(1, "")},
		{validate.CodeEntryDuplicate, entry(3, "")},
		{validate.CodeEntryDuplicate, entry(5, "")},
		{validate.CodeEntryVersion, entry(7, ".identifier")},
		{validate.CodeManifestEmpty, manifest(8, "")},
		{validate.CodeEntryMember, entry(9, ".identifier")},
		{validate.CodeEntryMember, entry(9, ".type")},
		{validate.CodePublisherMember, entry(9, ".publisher.identifier")},
		{validate.CodePublisherMember, entry(9, ".publisher.displayName")},
		{validate.CodeManifestContributor, manifest(9, ".contributor")},
		{validate.CodeManifestEmpty, manifest(9, "")},
		{validate.CodeTimestamp, entry(10, ".updatedAt")},
		{validate.CodeExtensionKey, entry(11, ".extensions")},
		{validate.CodeExtensionKey, manifest(11, ".extensions")},
		{validate.CodeManifestEmpty, manifest(12, "")},
		{validate.CodeManifestSignedMember, manifest(13, ".subject")},
		{validate.CodeSignatureMember, manifest(13, ".signature.issuedAt")},
		{validate.CodeEntryDigest, entry(13, ".digest")},
		{validate.CodeTimestamp, manifest(14, ".signature.issuedAt")},
		{validate.CodeSubjectMismatch, manifest(15, ".subject.identifier")},
		{validate.CodeSubjectMismatch, manifest(15, ".subject.version")},
		{validate.CodeSubjectMismatch, manifest(15, ".subject.type")},
		{validate.CodeSubjectMismatch, manifest(15, ".subject.digest")},
		{validate.CodeNestedInvalid, entry(16, ".data")},
		{validate.CodeManifestSigner, manifest(17, ".signature.signer")},
		{validate.CodeSignatureType, manifest(18, ".signature.jws")},
		{validate.CodeSignatureType, manifest(19, ".signature.jws")},
		{validate.CodeSignatureSigner, manifest(20, ".signature.signer")},
		{validate.CodeManifestSigner, manifest(20, ".signature.signer")},
		{validate.CodeManifestContributorURI, manifest(21, ".contributor")},
		{validate.CodeSignatureMember, manifest(22, ".signature.profile")},
		{validate.CodeSignatureMember, manifest(22, ".signature.jws")},
	}

	wantWarnings := []diagnostic{
		{validate.CodeIdentifierNotURI, entry(10, ".identifier")},
		{validate.CodeProfileSigner, manifest(13, ".signature.signer")},
		{validate.CodeProfileKeyID, manifest(13, ".signature.jws")},
		{validate.CodeSignatureExpired, manifest(14, ".signature.expiresAt")},
		{validate.CodeProfileSigner, manifest(15, ".signature.signer")},
		{validate.CodeProfileKeyID, manifest(15, ".signature.jws")},
		{validate.CodeProfileSigner, manifest(20, ".signature.signer")},
	}

	compare(t, "error", result.Errors, wantErrors)
	compare(t, "warning", result.Warnings, wantWarnings)
}

func TestValidate_NoneSignaturesAndWeakDigests(t *testing.T) {
	result := validate.Validate(parse(t, "weak_signature.json"))

	want := []diagnostic{
		{validate.CodeDigestInvalid, entry(1, ".digest")},
		{validate.CodeSignatureAlgorithm, manifest(1, ".signature.jws")},
		{validate.CodeDigestInvalid, manifest(1, ".subject.digest")},
		{validate.CodeSignatureAlgorithm, manifest(2, ".signature.jws")},
		{validate.CodeSignatureMalformed, manifest(3, ".signature.jws")},
		{validate.CodeDigestInvalid, manifest(4, ".attestations[0].digest")},
		{validate.CodeDigestInvalid, manifest(4, ".provenance[0].sourceDigest")},
	}

	compare(t, "error", result.Errors, want)
}

func TestValidate_DidWebSignerProfile(t *testing.T) {
	result := validate.Validate(parse(t, "profile.json"))

	wantWarnings := []diagnostic{
		{validate.CodeProfileSigner, manifest(3, ".signature.signer")},
		{validate.CodeProfileAlgorithm, manifest(5, ".signature.jws")},
		{validate.CodeProfileKeyID, manifest(6, ".signature.jws")},
		{validate.CodeProfileKeyID, manifest(7, ".signature.jws")},
		{validate.CodeProfileKeyID, manifest(8, ".signature.jws")},
		{validate.CodeProfileHeader, manifest(9, ".signature.jws")},
		{validate.CodeProfileSigner, manifest(10, ".signature.signer")},
		{validate.CodeProfileSigner, manifest(15, ".signature.signer")},
	}

	wantErrors := []diagnostic{
		{validate.CodeSignatureB64, manifest(11, ".signature.jws")},
		{validate.CodeSignatureMalformed, manifest(12, ".signature.jws")},
		{validate.CodeSignatureForm, manifest(13, ".signature.jws")},
	}

	compare(t, "warning", result.Warnings, wantWarnings)
	compare(t, "error", result.Errors, wantErrors)
}

func TestValidate_OnlyPublisherMakesCatalogTrusted(t *testing.T) {
	doc := parse(t, "profile.json")

	for i := range doc.Entries {
		alone := *doc
		alone.Entries = []catalog.CatalogEntry{doc.Entries[i]}

		trusted := validate.Validate(&alone).ConformanceLevel == validate.Trusted
		if trusted != (i == 0) {
			t.Errorf("entry %d: trusted = %t, want %t", i, trusted, i == 0)
		}
	}
}

func TestValidate_AssessorAloneIsNotTrusted(t *testing.T) {
	doc := parse(t, "trust_clean.json")
	trustManifest := &doc.Entries[0].TrustManifests[0]

	trustManifest.Contributor = assessorDID
	trustManifest.Signature.Signer = assessorDID

	result := validate.Validate(doc)

	if !result.IsValid || result.ConformanceLevel != validate.Discoverable {
		t.Errorf("valid=%t level=%v, want a valid Discoverable catalog (errors %+v)",
			result.IsValid, result.ConformanceLevel, result.Errors)
	}
}

func TestValidate_OtherContributorDoesNotHoldBackPublisher(t *testing.T) {
	doc := parse(t, "trust_clean.json")
	assessor := doc.Entries[0].TrustManifests[0]

	assessor.Contributor = assessorDID
	assessor.Signature = nil
	doc.Entries[0].TrustManifests = append(doc.Entries[0].TrustManifests, assessor)

	result := validate.Validate(doc)

	if !result.IsValid || result.ConformanceLevel != validate.Trusted {
		t.Errorf("valid=%t level=%v, want a valid Trusted catalog (errors %+v)",
			result.IsValid, result.ConformanceLevel, result.Errors)
	}
}

func TestValidate_ExpiryFollowsClock(t *testing.T) {
	doc := parse(t, "trust_clean.json")
	doc.Entries[0].TrustManifests[0].Signature.ExpiresAt = "2026-06-01T00:00:00Z"

	clock := func(value string) validate.Option {
		now, err := time.Parse(time.RFC3339, value)
		if err != nil {
			t.Fatalf("parse clock: %v", err)
		}

		return validate.WithClock(func() time.Time { return now })
	}

	before := validate.Validate(doc, clock("2026-05-31T00:00:00Z"))
	if before.ConformanceLevel != validate.Trusted || len(before.Warnings) != 0 {
		t.Errorf("before expiry: level=%v warnings=%+v", before.ConformanceLevel, before.Warnings)
	}

	after := validate.Validate(doc, clock("2026-06-02T00:00:00Z"))
	if !after.IsValid || after.ConformanceLevel != validate.Discoverable {
		t.Errorf("after expiry: valid=%t level=%v", after.IsValid, after.ConformanceLevel)
	}

	compare(t, "warning", after.Warnings,
		[]diagnostic{{validate.CodeSignatureExpired, manifest(0, ".signature.expiresAt")}})
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
