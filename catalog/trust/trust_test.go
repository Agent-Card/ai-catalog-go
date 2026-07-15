// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package trust_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
	"github.com/agntcy/ai-catalog-go-sdk/catalog/trust"
)

// SHA-256 of the ASCII bytes "test".
const testSHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func mustParse(t *testing.T, doc string) *catalog.AICatalog {
	t.Helper()

	c, err := catalog.ParseString(doc)
	if err != nil {
		t.Fatalf("parse document: %v", err)
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
	c := mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:agent", "displayName": "Agent",
			 "type": "application/json", "url": "https://example.com/agent.json",
			 "trustManifest": {
				"identity": "urn:example:agent",
				"signature": "header..signature",
				"metadata": {"zeta": true, "alpha": 1}
			 }}
		]
	}`)

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
	report := trust.AnalyzeCatalog(mustParse(t, `{
		"specVersion": "1.0",
		"host": {
			"displayName": "Example Host",
			"identifier": "did:web:example.com",
			"trustManifest": {
				"identity": "did:web:other.example.com",
				"signature": "not-a-detached-jws"
			}
		},
		"entries": [
			{"identifier": "urn:air:acme.com:agent:artifact", "displayName": "Artifact",
			 "type": "application/json", "url": "https://example.com/artifact.json",
			 "trustManifest": {
				"identity": "did:web:evil.example",
				"signature": "header.payload.signature",
				"trustSchema": {"identifier": "", "version": ""},
				"attestations": [
					{"type": "", "uri": "", "digest": "md5:abcd"}
				],
				"provenance": [
					{"relation": "", "sourceId": "", "sourceDigest": "sha256:not-hex!"}
				]
			 }}
		]
	}`))

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
	report := trust.AnalyzeCatalog(mustParse(t, `{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:artifact", "displayName": "Artifact",
			 "type": "application/json", "url": "https://example.com/artifact.json",
			 "trustManifest": {"identity": "plain-identifier"}}
		]
	}`))

	if !containsFinding(report, "trust manifest identity SHOULD be a URI-like identifier") {
		t.Errorf("expected URI-like identity warning, got: %+v", report.Findings)
	}

	if containsFinding(report, "MUST align with entry identifier publisher domain") {
		t.Errorf("did not expect a domain-alignment error for a non-urn:air identifier: %+v", report.Findings)
	}
}

func TestAnalyzeCatalog_Clean(t *testing.T) {
	report := trust.AnalyzeCatalog(mustParse(t, `{
		"specVersion": "1.0",
		"host": {
			"displayName": "Example Host",
			"identifier": "did:web:example.com",
			"trustManifest": {"identity": "did:web:example.com", "signature": "header..signature"}
		},
		"entries": [
			{"identifier": "urn:example:artifact", "displayName": "Artifact",
			 "type": "application/json", "url": "https://example.com/artifact.json",
			 "trustManifest": {
				"identity": "urn:example:artifact",
				"signature": "header..signature",
				"trustSchema": {"identifier": "urn:trust:example", "version": "1.0"},
				"attestations": [
					{"type": "publisher-identity", "uri": "https://example.com/p.jwt",
					 "mediaType": "application/jwt", "digest": "sha256:`+testSHA256+`"}
				],
				"provenance": [
					{"relation": "publishedFrom", "sourceId": "https://github.com/example/repo",
					 "sourceDigest": "sha256:`+testSHA256+`"}
				]
			 }}
		]
	}`))

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
