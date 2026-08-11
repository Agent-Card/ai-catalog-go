// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/agntcy/ai-catalog-go/catalog"
	"github.com/agntcy/ai-catalog-go/internal/fixture"
	"github.com/agntcy/ai-catalog-go/trust"
)

// SHA-256 of the ASCII bytes "test".
const testSHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// parse parses one of the shared fixture documents.
func parse(t *testing.T, data []byte) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.Parse(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	return c
}

func TestParseDigest_Valid(t *testing.T) {
	d, err := trust.ParseDigest("sha256:" + testSHA256)
	if err != nil {
		t.Fatalf("ParseDigest error: %v", err)
	}

	if d.Algorithm() != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", d.Algorithm())
	}

	if !d.VerifyBytes([]byte("test")) {
		t.Error("VerifyBytes should match SHA-256 of \"test\"")
	}
}

func TestVerifyDigest(t *testing.T) {
	ok, err := trust.VerifyDigest("sha256:"+testSHA256, []byte("test"))
	if err != nil {
		t.Fatalf("VerifyDigest error: %v", err)
	}

	if !ok {
		t.Error("VerifyDigest should report a match")
	}

	ok, err = trust.VerifyDigest("sha256:"+testSHA256, []byte("tampered"))
	if err != nil {
		t.Fatalf("VerifyDigest error: %v", err)
	}

	if ok {
		t.Error("VerifyDigest should not match tampered bytes")
	}
}

func TestParseDigest_Errors(t *testing.T) {
	cases := []struct {
		value string
		want  error
	}{
		{"md5:abcd", trust.ErrWeakDigestAlgorithm},
		{"sha1:abcd", trust.ErrWeakDigestAlgorithm},
		{"crc32:abcd", trust.ErrUnsupportedDigestAlgorithm},
		{"sha256:not-hex!", trust.ErrInvalidDigestHex},
		{"sha256:abc", trust.ErrInvalidDigestHex},                      // too short (and odd length)
		{"sha256:" + testSHA256 + "ab", trust.ErrInvalidDigestHex},     // too long for sha256
		{"sha256:" + testSHA256[:63] + "g", trust.ErrInvalidDigestHex}, // right length, non-hex char
		{"missing-colon", trust.ErrInvalidDigestFormat},
		{"sha256:", trust.ErrInvalidDigestFormat},
	}

	for _, tc := range cases {
		_, err := trust.ParseDigest(tc.value)
		if !errors.Is(err, tc.want) {
			t.Errorf("ParseDigest(%q) error = %v, want %v", tc.value, err, tc.want)
		}
	}
}

func TestCanonicalizeTrustManifest_StripsSignatureAndSortsKeys(t *testing.T) {
	c := parse(t, fixture.TrustCleanJSON)

	manifest := c.Entries[0].TrustManifest
	if manifest == nil {
		t.Fatal("expected entry trust manifest")
	}

	canonical, err := trust.CanonicalizeTrustManifest(manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	if strings.Contains(canonical, "signature") {
		t.Errorf("canonical form should not contain signature: %s", canonical)
	}

	// Keys within metadata must be sorted (alpha before zeta), and integer
	// values must be preserved exactly.
	if !strings.Contains(canonical, `"alpha":1`) {
		t.Errorf("expected integer metadata preserved: %s", canonical)
	}

	if strings.Index(canonical, "alpha") > strings.Index(canonical, "zeta") {
		t.Errorf("keys should be sorted (alpha before zeta): %s", canonical)
	}
}

func TestAnalyzeCatalog_Findings(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.TrustFindingsJSON))

	if report.Host == nil || len(report.Host.Findings) != 2 {
		t.Fatalf("expected 2 host findings, got: %+v", report.Host)
	}

	if len(report.Entries) != 1 {
		t.Fatalf("expected 1 entry report, got %d", len(report.Entries))
	}

	wants := []string{
		"host trustManifest.identity 'did:web:other.example.com' SHOULD match host.identifier 'did:web:example.com'",
		"signature must use detached JWS compact serialization",
		"trustManifest.identity domain 'evil.example' MUST align with entry identifier publisher domain 'acme.com'",
		"weaker than SHA-256",
		"attestation type must not be empty",
		"provenance relation must not be empty",
	}

	for _, want := range wants {
		if !containsFinding(report, want) {
			t.Errorf("missing expected finding containing %q", want)
		}
	}
}

func TestAnalyzeCatalog_NonURIIdentityWarns(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.TrustNonURIJSON))

	if !containsFinding(report, "trust manifest identity SHOULD be a URI-like identifier") {
		t.Errorf("expected URI-like identity warning, got: %+v", report.Findings)
	}

	if containsFinding(report, "MUST align with entry identifier publisher domain") {
		t.Errorf("did not expect a domain-alignment error for a non-urn:air identifier: %+v", report.Findings)
	}
}

func TestAnalyzeCatalog_IdentityWithoutTrustDomainFailsBinding(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.UnboundIdentityJSON))

	want := "trustManifest.identity 'urn:acme:agent:finance' MUST carry a trust domain " +
		"aligned with entry identifier publisher domain 'acme.com'"

	if !containsFinding(report, want) {
		t.Errorf("missing expected finding %q, got: %+v", want, report.Findings)
	}
}

func TestAnalyzeCatalog_Clean(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.TrustCleanJSON))

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings, got: %+v", report.Findings)
	}

	if report.Host == nil || !report.Host.HasSignature {
		t.Error("expected host manifest with signature")
	}

	if len(report.Entries) != 1 || report.Entries[0].AttestationCount != 1 {
		t.Errorf("unexpected entry report: %+v", report.Entries)
	}
}

func containsFinding(report trust.CatalogTrustReport, substr string) bool {
	for _, f := range report.Findings {
		if strings.Contains(f.Message, substr) {
			return true
		}
	}

	return false
}
