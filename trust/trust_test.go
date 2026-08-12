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

	// Extension keys must be sorted (alpha before zeta), and integer values
	// must be preserved exactly.
	if !strings.Contains(canonical, `"com.example.alpha":1`) {
		t.Errorf("expected integer extension value preserved: %s", canonical)
	}

	if strings.Index(canonical, "alpha") > strings.Index(canonical, "zeta") {
		t.Errorf("keys should be sorted (alpha before zeta): %s", canonical)
	}

	// The subject and issuedAt a signature commits to stay in the payload.
	for _, member := range []string{"subject", "issuedAt"} {
		if !strings.Contains(canonical, member) {
			t.Errorf("expected %q in the signed payload: %s", member, canonical)
		}
	}
}

// RFC 8785 Appendix B, which exercises key ordering, minimal string escaping,
// and ECMAScript number formatting in a single document.
func TestCanonicalize_RFC8785AppendixB(t *testing.T) {
	input := []byte(`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`)

	want := `{"literals":[null,true,false],` +
		`"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],` +
		"\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"

	got, err := trust.Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	if string(got) != want {
		t.Errorf("Canonicalize =\n  %s\nwant\n  %s", got, want)
	}
}

func TestCanonicalize_NumberFormatting(t *testing.T) {
	cases := map[string]string{
		"0":                      "0",
		"-0":                     "0",
		"1.0":                    "1",
		"1.5":                    "1.5",
		"0.001":                  "0.001",
		"0.000001":               "0.000001",
		"1e-7":                   "1e-7",
		"1e20":                   "100000000000000000000",
		"1e21":                   "1e+21",
		"5e-324":                 "5e-324",
		"1.7976931348623157e308": "1.7976931348623157e+308",
		"-1.5e-9":                "-1.5e-9",
	}

	for input, want := range cases {
		got, err := trust.Canonicalize([]byte(`{"n":` + input + `}`))
		if err != nil {
			t.Errorf("Canonicalize(%s) error: %v", input, err)

			continue
		}

		if want = `{"n":` + want + `}`; string(got) != want {
			t.Errorf("Canonicalize(%s) = %s, want %s", input, got, want)
		}
	}
}

// encoding/json escapes &, < and > as \u0026, \u003c and \u003e, which would
// change the bytes a signature is computed over.
func TestCanonicalize_DoesNotEscapeHTMLCharacters(t *testing.T) {
	got, err := trust.Canonicalize([]byte(`{"a":"x < y & z > w"}`))
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	if want := `{"a":"x < y & z > w"}`; string(got) != want {
		t.Errorf("Canonicalize = %s, want %s", got, want)
	}
}

// Sorting UTF-8 bytes would place U+E000 before the surrogate pair of U+1F600;
// UTF-16 code unit order puts the surrogate pair first.
func TestCanonicalize_SortsKeysByUTF16CodeUnit(t *testing.T) {
	got, err := trust.Canonicalize([]byte(`{"\ue000":1,"\ud83d\ude00":2}`))
	if err != nil {
		t.Fatalf("Canonicalize error: %v", err)
	}

	if want := "{\"\U0001F600\":2,\"\uE000\":1}"; string(got) != want {
		t.Errorf("Canonicalize = %s, want %s", got, want)
	}
}

// Canonicalize rejects input that is not I-JSON.
func TestCanonicalize_Errors(t *testing.T) {
	cases := map[string]string{
		"trailing content":       `{"a":1} trailing`,
		"truncated object":       `{`,
		"non-finite number":      `{"n":1e400}`,
		"malformed number":       `{"n":01}`,
		"duplicate member names": `{"a":1,"a":2}`,
		"lone high surrogate":    `{"a":"\ud800"}`,
		"lone low surrogate":     `{"a":"\udc00"}`,
		"invalid UTF-8":          "{\"a\":\"\xff\"}",
	}

	for name, input := range cases {
		if _, err := trust.Canonicalize([]byte(input)); !errors.Is(err, trust.ErrUncanonicalizableJSON) {
			t.Errorf("Canonicalize(%s): got error %v, want ErrUncanonicalizableJSON", name, err)
		}
	}
}

// CanonicalizeForSignature works on the original bytes, so members the SDK does
// not model still take part in the signed payload.
func TestCanonicalizeForSignature_KeepsUnmodelledMembers(t *testing.T) {
	got, err := trust.CanonicalizeForSignature(
		[]byte(`{"signature":"sig","identity":"urn:example","futureMember":42}`))
	if err != nil {
		t.Fatalf("CanonicalizeForSignature error: %v", err)
	}

	if want := `{"futureMember":42,"identity":"urn:example"}`; string(got) != want {
		t.Errorf("CanonicalizeForSignature = %s, want %s", got, want)
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

func TestAnalyzeCatalog_RejectsNonAsymmetricSignatureAlgorithms(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.WeakSignatureJSON))

	wants := []string{
		"signature algorithm 'none' must be rejected",
		"signature algorithm 'HS256' must be rejected",
	}

	for _, want := range wants {
		if !containsFinding(report, want) {
			t.Errorf("missing expected finding containing %q, got: %+v", want, report.Findings)
		}
	}
}

func TestAnalyzeCatalog_SignatureRequiresSubjectAndIssuedAt(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.InvalidJSON))

	wants := []string{
		"a signed trust manifest must carry a subject",
		"a signed trust manifest must carry an issuedAt timestamp",
	}

	for _, want := range wants {
		if !containsFinding(report, want) {
			t.Errorf("missing expected finding containing %q, got: %+v", want, report.Findings)
		}
	}
}

func TestAnalyzeCatalog_WarnsOnExpiredManifest(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.InvalidJSON))

	if !containsFinding(report, "SHOULD be rejected") {
		t.Errorf("expected an expiry warning, got: %+v", report.Findings)
	}
}

func TestAnalyzeCatalog_ChecksCatalogLevelSignature(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.InvalidJSON))

	if !report.HasSignature {
		t.Error("expected the catalog-level signature to be reported")
	}

	if !containsFinding(report, "signature must use detached JWS compact serialization") {
		t.Errorf("expected a malformed catalog signature finding, got: %+v", report.Findings)
	}
}

func TestAnalyzeCatalog_Clean(t *testing.T) {
	report := trust.AnalyzeCatalog(parse(t, fixture.TrustCleanJSON))

	if len(report.Findings) != 0 {
		t.Errorf("expected no findings, got: %+v", report.Findings)
	}

	if !report.HasSignature {
		t.Error("expected a catalog-level signature")
	}

	if report.Host == nil || !report.Host.HasSignature || !report.Host.HasSubject {
		t.Error("expected host manifest with a signature and subject")
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
