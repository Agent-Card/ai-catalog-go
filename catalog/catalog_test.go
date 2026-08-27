// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
)

const (
	testSpecVersion = "1.0"
	fixtureEntries  = 11
	financeID       = "urn:example:agent:finance-v1"
	nlpID           = "urn:example:data:nlp-corpus"
	embeddingID     = "urn:example:model:embedding-v2"
	taggedID        = "urn:example:model:tagged"
	modifiedName    = "Modified"
)

// validCatalogJSON is the shared, spec-valid fixture used by the parsing and
// query tests.
var validCatalogJSON = fixture.CatalogJSON

func validCatalog(t *testing.T) *AICatalog {
	t.Helper()

	c, err := Parse(validCatalogJSON)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	return c
}

// parseFixture parses one of the shared fixture documents.
func parseFixture(t *testing.T, data []byte) *AICatalog {
	t.Helper()

	c, err := Parse(data)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	return c
}

func TestParse_Valid(t *testing.T) {
	c := validCatalog(t)

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q, want %q", c.SpecVersion, testSpecVersion)
	}

	if c.Host == nil || c.Host.Identifier != "did:example:org-acme-corp" {
		t.Errorf("unexpected host: %+v", c.Host)
	}

	if len(c.Entries) != fixtureEntries {
		t.Fatalf("len(Entries) = %d, want %d", len(c.Entries), fixtureEntries)
	}

	if c.Entries[0].Type != "application/a2a-agent-card+json" {
		t.Errorf("entry[0].Type = %q", c.Entries[0].Type)
	}
}

// The four entry points wrap the same decoder, so one document exercises all.
func TestParse_AllInputForms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, validCatalogJSON, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	forms := map[string]func() (*AICatalog, error){
		"Parse":       func() (*AICatalog, error) { return Parse(validCatalogJSON) },
		"ParseString": func() (*AICatalog, error) { return ParseString(string(validCatalogJSON)) },
		"ParseReader": func() (*AICatalog, error) { return ParseReader(bytes.NewReader(validCatalogJSON)) },
		"ParseFile":   func() (*AICatalog, error) { return ParseFile(path) },
	}

	for name, parse := range forms {
		c, err := parse()
		if err != nil {
			t.Errorf("%s error: %v", name, err)

			continue
		}

		if c.SpecVersion != testSpecVersion || len(c.Entries) != fixtureEntries {
			t.Errorf("%s: SpecVersion = %q, len(Entries) = %d",
				name, c.SpecVersion, len(c.Entries))
		}
	}
}

func TestParse_Errors(t *testing.T) {
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Error("Parse(invalid JSON): expected an error")
	}

	if _, err := ParseFile("/nonexistent/path/catalog.json"); err == nil {
		t.Error("ParseFile(missing file): expected an error")
	}
}

func TestToJSON_RoundTrip(t *testing.T) {
	original := validCatalog(t)

	data, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	if !strings.Contains(string(data), `"specVersion":"1.0"`) {
		t.Errorf("compact JSON missing specVersion: %s", data)
	}

	if !strings.Contains(string(data), `"type":"application/a2a-agent-card+json"`) {
		t.Errorf("compact JSON should serialize entry kind as 'type': %s", data)
	}

	restored, err := Parse(data)
	if err != nil {
		t.Fatalf("re-parse error: %v", err)
	}

	if len(restored.Entries) != len(original.Entries) {
		t.Errorf("entry count mismatch: got %d, want %d", len(restored.Entries), len(original.Entries))
	}
}

// Extensions, the catalog signature, and the trust manifest's subject binding
// must survive a parse/serialize round trip under their spec member names.
func TestRoundTrip_PreservesExtensionsSignatureAndSubject(t *testing.T) {
	const doc = `{"specVersion":"1.0","signature":"eyJhbGciOiJFUzI1NiJ9..c2ln",` +
		`"extensions":{"com.example.flag":true},` +
		`"entries":[{"identifier":"urn:example:a","type":"application/json",` +
		`"url":"https://example.com/a.json",` +
		`"extensions":{"com.example.score":0.5},` +
		`"trustManifest":{"identity":"urn:example:a",` +
		`"subject":{"type":"application/json","digest":"sha256:abc",` +
		`"url":"https://example.com/a.json"},` +
		`"issuedAt":"2026-03-15T10:00:00Z","expiresAt":"2126-03-15T10:00:00Z",` +
		`"extensions":{"com.example.note":"x"}}}]}`

	c, err := ParseString(doc)
	if err != nil {
		t.Fatalf("ParseString error: %v", err)
	}

	if c.Signature == "" {
		t.Error("catalog signature was dropped on parse")
	}

	if _, ok := c.Extensions["com.example.flag"]; !ok {
		t.Errorf("catalog extensions were dropped on parse: %+v", c.Extensions)
	}

	entry := &c.Entries[0]
	if _, ok := entry.Extensions["com.example.score"]; !ok {
		t.Errorf("entry extensions were dropped on parse: %+v", entry.Extensions)
	}

	manifest := entry.TrustManifest
	if manifest.Subject == nil || manifest.Subject.Digest != "sha256:abc" {
		t.Errorf("trust manifest subject was dropped on parse: %+v", manifest.Subject)
	}

	if manifest.IssuedAt == "" || manifest.ExpiresAt == "" {
		t.Errorf("trust manifest timestamps were dropped on parse: %+v", manifest)
	}

	if _, ok := manifest.Extensions["com.example.note"]; !ok {
		t.Errorf("trust manifest extensions were dropped on parse: %+v", manifest.Extensions)
	}

	data, err := c.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	for _, want := range []string{
		`"extensions":{"com.example.flag":true}`,
		`"subject":{"type":"application/json","digest":"sha256:abc"`,
		`"issuedAt":"2026-03-15T10:00:00Z"`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("serialized document missing %s: %s", want, data)
		}
	}

	if strings.Contains(string(data), `"metadata"`) {
		t.Errorf("extensions must not serialize as 'metadata': %s", data)
	}
}

func TestMarshalJSON_EmptyEntriesSerializesAsArray(t *testing.T) {
	c := &AICatalog{SpecVersion: testSpecVersion}

	data, err := c.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	if !strings.Contains(string(data), `"entries":[]`) {
		t.Errorf("empty entries should serialize as []: %s", data)
	}

	if strings.Contains(string(data), `"entries":null`) {
		t.Errorf("entries must never serialize as null: %s", data)
	}
}

func TestIndentedOutputRoundTrips(t *testing.T) {
	c := validCatalog(t)

	data, err := c.ToJSONIndent()
	if err != nil {
		t.Fatalf("ToJSONIndent error: %v", err)
	}

	if !strings.Contains(string(data), "\n") {
		t.Error("ToJSONIndent should emit newlines")
	}

	var buf strings.Builder
	if err := c.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	for name, out := range map[string]string{"ToJSONIndent": string(data), "WriteJSON": buf.String()} {
		restored, err := ParseString(out)
		if err != nil {
			t.Errorf("%s output does not parse: %v", name, err)

			continue
		}

		if len(restored.Entries) != len(c.Entries) {
			t.Errorf("%s: len(Entries) = %d, want %d",
				name, len(restored.Entries), len(c.Entries))
		}
	}
}

func TestGetByID(t *testing.T) {
	c := validCatalog(t)

	entry, ok := c.GetByID(financeID)
	if !ok {
		t.Fatalf("GetByID(%s): expected hit", financeID)
	}

	if entry.DisplayName != "Finance Agent" {
		t.Errorf("DisplayName = %q", entry.DisplayName)
	}

	if _, ok := c.GetByID("urn:does:not:exist"); ok {
		t.Error("GetByID(unknown): expected miss")
	}

	// Exact-match only.
	if _, ok := c.GetByID("finance"); ok {
		t.Error("GetByID should be exact-match only")
	}
}

func TestGetByID_ReturnsPointerIntoSlice(t *testing.T) {
	c := validCatalog(t)

	entry, ok := c.GetByID(nlpID)
	if !ok {
		t.Fatal("expected hit")
	}

	entry.DisplayName = modifiedName

	if again, _ := c.GetByID(nlpID); again.DisplayName != modifiedName {
		t.Error("GetByID should return a pointer into the Entries slice")
	}
}

func TestGetByType(t *testing.T) {
	c := validCatalog(t)

	agents := c.GetByType("application/a2a-agent-card+json")
	if len(agents) != 4 || agents[0].Identifier != financeID {
		t.Errorf("GetByType(agent) = %+v", agents)
	}

	if got := c.GetByType("application/does-not-exist"); got != nil {
		t.Errorf("GetByType(unknown) = %+v, want nil", got)
	}
}

func TestGetByTag(t *testing.T) {
	c := validCatalog(t)

	finance := c.GetByTag("finance")
	if len(finance) != 1 || finance[0].Identifier != financeID {
		t.Errorf("GetByTag(finance) = %+v", finance)
	}

	if got := c.GetByTag("dataset"); len(got) != 1 || got[0].Identifier != nlpID {
		t.Errorf("GetByTag(dataset) = %+v", got)
	}

	if got := c.GetByTag("does-not-exist"); got != nil {
		t.Errorf("GetByTag(unknown) = %+v, want nil", got)
	}
}

func TestGetByPublisher(t *testing.T) {
	c := validCatalog(t)

	acme := c.GetByPublisher("did:example:acme")
	if len(acme) != 2 || acme[0].Identifier != financeID || acme[1].Identifier != nlpID {
		t.Errorf("GetByPublisher(acme) = %+v", acme)
	}

	if got := c.GetByPublisher("did:example:other"); len(got) != 1 || got[0].Identifier != embeddingID {
		t.Errorf("GetByPublisher(other) = %+v", got)
	}

	if got := c.GetByPublisher("did:example:missing"); got != nil {
		t.Errorf("GetByPublisher(unknown) = %+v, want nil", got)
	}
}

const versionedID = "urn:air:acme.com:agent:finance"

func TestGetByIDAndVersion(t *testing.T) {
	c := validCatalog(t)

	entry, ok := c.GetByIDAndVersion(versionedID, "2.0.1")
	if !ok || entry.Version != "2.0.1" {
		t.Fatalf("GetByIDAndVersion = %+v, ok=%v", entry, ok)
	}

	if _, ok := c.GetByIDAndVersion(versionedID, "9.9.9"); ok {
		t.Error("expected miss for unknown version")
	}
}

func TestVersions(t *testing.T) {
	c := validCatalog(t)

	if got := c.Versions(versionedID); len(got) != 3 {
		t.Errorf("Versions = %d, want 3", len(got))
	}

	if got := c.Versions("urn:does:not:exist"); got != nil {
		t.Errorf("Versions(unknown) = %+v, want nil", got)
	}
}

func TestGetLatest_Semver(t *testing.T) {
	c := validCatalog(t)

	entry, ok := c.GetLatest(versionedID)
	if !ok || entry.Version != "2.1.0" {
		t.Fatalf("GetLatest = %+v, ok=%v, want version 2.1.0", entry, ok)
	}

	if _, ok := c.GetLatest("urn:does:not:exist"); ok {
		t.Error("expected miss for unknown identifier")
	}
}

func TestGetLatest_FallbackToUpdatedAt(t *testing.T) {
	// The invalid fixture's "urn:dup" pair is two unversioned entries sharing an
	// identifier, the shape that forces the updatedAt fallback.
	c := parseFixture(t, fixture.InvalidJSON)

	entry, ok := c.GetLatest("urn:dup")
	if !ok || entry.URL != "https://example.com/dup-new" {
		t.Fatalf("GetLatest (updatedAt fallback) = %+v, ok=%v", entry, ok)
	}
}

func TestGetLatest_PrefersSemverOverUnparseable(t *testing.T) {
	c := validCatalog(t)

	// taggedID has a "1.0.0" entry and a newer (by updatedAt) "latest" entry;
	// the parseable semver must win over the unparseable tag.
	entry, ok := c.GetLatest(taggedID)
	if !ok || entry.Version != "1.0.0" {
		t.Fatalf("GetLatest should prefer parseable semver, got %+v", entry)
	}
}

func TestResolveDisplayName(t *testing.T) {
	cases := []struct {
		entry CatalogEntry
		want  string
	}{
		{CatalogEntry{DisplayName: "Weather", Identifier: "urn:air:example.com:mcp:weather"}, "Weather"},
		{CatalogEntry{Identifier: "urn:air:example.com:mcp:weather"}, "weather"},
		{CatalogEntry{Identifier: "https://example.com/agents/research"}, "research"},
		{CatalogEntry{Identifier: "bare"}, "bare"},
	}

	for _, tc := range cases {
		if got := tc.entry.ResolveDisplayName(); got != tc.want {
			t.Errorf("ResolveDisplayName(%+v) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}

func TestSearch(t *testing.T) {
	c := validCatalog(t)

	cases := []struct {
		query string
		want  int
	}{
		{"nlp-corpus", 1},
		{"FINANCE", 4}, // finance-v1 entry plus the three versioned finance agents
		{"NLP Corpus", 1},
		{"financial queries", 1},
		{"dataset", 1},
		{"urn:example", 7},
		{"xyzzy-not-found", 0},
	}

	for _, tc := range cases {
		if got := len(c.Search(tc.query)); got != tc.want {
			t.Errorf("Search(%q) = %d results, want %d", tc.query, got, tc.want)
		}
	}
}

func TestSearchByRegex(t *testing.T) {
	c := validCatalog(t)

	results, err := c.SearchByRegex(`urn:example:(agent|data):.*`)
	if err != nil {
		t.Fatalf("SearchByRegex error: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}

	anchored, err := c.SearchByRegex(`^urn:example:model:embedding-v2`)
	if err != nil {
		t.Fatalf("SearchByRegex error: %v", err)
	}

	if len(anchored) != 1 || anchored[0].Identifier != embeddingID {
		t.Errorf("anchored search unexpected: %+v", anchored)
	}
}

func TestSearchByRegex_InvalidPattern(t *testing.T) {
	c := validCatalog(t)

	if _, err := c.SearchByRegex("[invalid("); err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}
