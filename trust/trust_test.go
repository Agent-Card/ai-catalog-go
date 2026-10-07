// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
	"github.com/Agent-Card/ai-catalog-go/trust"
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

// A manifest read from a document must canonicalize to what a verifier
// computes from the published bytes, whatever shape those bytes have. The
// struct cannot represent several of these shapes, so re-serializing it signs a
// different document than the producer did.
func TestCanonicalizeTrustManifest_MatchesPublishedBytes(t *testing.T) {
	cases := map[string]string{
		"empty attestations":  `{"identity":"urn:example:a","attestations":[]}`,
		"empty provenance":    `{"identity":"urn:example:a","provenance":[]}`,
		"empty extensions":    `{"identity":"urn:example:a","extensions":{}}`,
		"empty string member": `{"identity":"urn:example:a","identityType":""}`,
		"null member":         `{"identity":"urn:example:a","privacyPolicyUrl":null}`,
		"unknown member":      `{"identity":"urn:example:a","com.example.extra":{"a":1}}`,
		"unknown nested":      `{"identity":"urn:example:a","attestations":[{"type":"t","uri":"https://example.com/a","x":true}]}`,
		"empty nested array":  `{"identity":"urn:example:a","trustSchema":{"identifier":"i","version":"1","verificationMethods":[]}}`,
		"whitespace, order": `{
  "signature": "ZXlK..",
  "subject": {"url": "https://example.com/a", "digest": "sha256:` + testSHA256 + `", "type": "text/plain"},
  "identity": "urn:example:a"
}`,
	}

	for name, published := range cases {
		t.Run(name, func(t *testing.T) {
			want, err := trust.CanonicalizeForSignature([]byte(published))
			if err != nil {
				t.Fatalf("CanonicalizeForSignature error: %v", err)
			}

			var manifest catalog.TrustManifest
			if err := json.Unmarshal([]byte(published), &manifest); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}

			got, err := trust.CanonicalizeTrustManifest(&manifest)
			if err != nil {
				t.Fatalf("CanonicalizeTrustManifest error: %v", err)
			}

			if got != string(want) {
				t.Errorf("canonical form differs from the published bytes\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// The same holds for a manifest reached through a parsed catalog.
func TestCanonicalizeTrustManifest_FromParsedCatalog(t *testing.T) {
	const doc = `{"specVersion":"1.0","entries":[{"identifier":"urn:example:a","type":"text/plain",` +
		`"url":"https://example.com/a","trustManifest":{"identity":"urn:example:a","attestations":[],` +
		`"com.example.extra":1,"signature":"ZXlK.."}}]}`

	c := parse(t, []byte(doc))

	got, err := trust.CanonicalizeTrustManifest(c.Entries[0].TrustManifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	const want = `{"attestations":[],"com.example.extra":1,"identity":"urn:example:a"}`
	if got != want {
		t.Errorf("canonical form = %s, want %s", got, want)
	}
}

// Once a decoded manifest is changed, the bytes it was decoded from no longer
// describe it; the payload must follow the change rather than the old bytes.
func TestCanonicalizeTrustManifest_FollowsChangesAfterDecoding(t *testing.T) {
	var manifest catalog.TrustManifest
	if err := json.Unmarshal([]byte(`{"identity":"urn:example:a","com.example.extra":1}`), &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	manifest.Identity = "urn:example:b"

	got, err := trust.CanonicalizeTrustManifest(&manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	if !strings.Contains(got, "urn:example:b") || strings.Contains(got, "urn:example:a") {
		t.Errorf("payload should reflect the changed identity: %s", got)
	}
}

// A manifest built in code has no published bytes; empty slices and maps the
// caller set explicitly are kept rather than silently dropped.
func TestCanonicalizeTrustManifest_BuiltManifestKeepsEmptyCollections(t *testing.T) {
	manifest := &catalog.TrustManifest{
		Identity:     "urn:example:a",
		Attestations: []catalog.Attestation{},
		Provenance:   []catalog.ProvenanceLink{},
		Extensions:   map[string]json.RawMessage{},
	}

	got, err := trust.CanonicalizeTrustManifest(manifest)
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	const want = `{"attestations":[],"extensions":{},"identity":"urn:example:a","provenance":[]}`
	if got != want {
		t.Errorf("canonical form = %s, want %s", got, want)
	}

	// Unset collections stay out.
	got, err = trust.CanonicalizeTrustManifest(&catalog.TrustManifest{Identity: "urn:example:a"})
	if err != nil {
		t.Fatalf("CanonicalizeTrustManifest error: %v", err)
	}

	if got != `{"identity":"urn:example:a"}` {
		t.Errorf("canonical form = %s, want identity only", got)
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
