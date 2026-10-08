// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
)

const (
	financeID   = "urn:example:agent:finance-v1"
	nlpID       = "urn:example:data:nlp-corpus"
	embeddingID = "urn:example:model:embedding-v2"
	taggedID    = "urn:example:model:tagged"
	versionedID = "urn:air:acme.com:agent:finance"
)

func parseFixture(t *testing.T, name string) *AICatalog {
	t.Helper()

	c, err := Parse(fixture.Read(t, name))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	return c
}

func manifestShape(t *testing.T, name string) json.RawMessage {
	t.Helper()

	var shapes map[string]json.RawMessage
	if err := json.Unmarshal(fixture.Read(t, "manifest_shapes.json"), &shapes); err != nil {
		t.Fatalf("decode manifest shapes: %v", err)
	}

	shape, ok := shapes[name]
	if !ok {
		t.Fatalf("no manifest shape %q", name)
	}

	return shape
}

func TestParse(t *testing.T) {
	doc := fixture.Read(t, "catalog.json")
	path := filepath.Join(t.TempDir(), "catalog.json")

	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	forms := map[string]func() (*AICatalog, error){
		"Parse":       func() (*AICatalog, error) { return Parse(doc) },
		"ParseString": func() (*AICatalog, error) { return ParseString(string(doc)) },
		"ParseReader": func() (*AICatalog, error) { return ParseReader(bytes.NewReader(doc)) },
		"ParseFile":   func() (*AICatalog, error) { return ParseFile(path) },
	}

	for name, parse := range forms {
		c, err := parse()
		if err != nil {
			t.Errorf("%s error: %v", name, err)

			continue
		}

		if len(c.Entries) != 11 {
			t.Errorf("%s: %d entries, want 11", name, len(c.Entries))
		}
	}

	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

// Parsing then serializing must not drop or invent any member.
func TestSerialize_RoundTrips(t *testing.T) {
	for _, name := range []string{"catalog.json", "trust_clean.json", "profile.json"} {
		t.Run(name, func(t *testing.T) {
			original := fixture.Read(t, name)

			out, err := parseFixture(t, name).ToJSON()
			if err != nil {
				t.Fatalf("ToJSON error: %v", err)
			}

			var want, got any
			if err := json.Unmarshal(original, &want); err != nil {
				t.Fatalf("decode original: %v", err)
			}

			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatalf("decode output: %v", err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip changed the document\n got: %s\nwant: %s", out, original)
			}
		})
	}
}

func TestSerialize_EmptyEntriesIsAnArray(t *testing.T) {
	out, err := (&AICatalog{SpecVersion: "1.0"}).ToJSON()
	if err != nil {
		t.Fatalf("ToJSON error: %v", err)
	}

	if !strings.Contains(string(out), `"entries":[]`) {
		t.Errorf("empty entries must serialize as []: %s", out)
	}
}

func TestLookups(t *testing.T) {
	c := parseFixture(t, "catalog.json")

	identifiers := func(entries []*CatalogEntry) []string {
		ids := make([]string, 0, len(entries))

		for _, entry := range entries {
			ids = append(ids, entry.Identifier)
		}

		return ids
	}

	tests := []struct {
		name string
		got  []string
		want []string
	}{
		{"by type", identifiers(c.GetByType(MediaTypeA2AAgentCard)), []string{financeID, versionedID, versionedID, versionedID}},
		{"by tag", identifiers(c.GetByTag("finance")), []string{financeID}},
		{"by publisher", identifiers(c.GetByPublisher("did:example:acme")), []string{financeID, nlpID}},
		{"versions", identifiers(c.Versions(versionedID)), []string{versionedID, versionedID, versionedID}},
		{"unknown", identifiers(c.GetByTag("does-not-exist")), []string{}},
	}

	for _, tc := range tests {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}

	if entry, ok := c.GetByID(embeddingID); !ok || entry.Identifier != embeddingID {
		t.Errorf("GetByID = %v, %t", entry, ok)
	}

	if _, ok := c.GetByID("embedding"); ok {
		t.Error("GetByID must match the whole identifier")
	}

	if entry, ok := c.GetByIDAndVersion(versionedID, "2.0.1"); !ok || entry.Version != "2.0.1" {
		t.Errorf("GetByIDAndVersion = %v, %t", entry, ok)
	}
}

func TestGetLatest(t *testing.T) {
	c := parseFixture(t, "catalog.json")

	tests := []struct {
		name       string
		catalog    *AICatalog
		identifier string
		wantURL    string
	}{
		{"highest semver", c, versionedID, "https://example.com/finance/2.1.0.json"},
		{"parseable semver over a newer tag", c, taggedID, "https://example.com/tagged/semver.bin"},
		{"updatedAt when unversioned", parseFixture(t, "invalid.json"), "urn:dup", "https://example.com/dup-new"},
	}

	for _, tc := range tests {
		entry, ok := tc.catalog.GetLatest(tc.identifier)
		if !ok || entry.URL != tc.wantURL {
			t.Errorf("%s: got %v, want url %s", tc.name, entry, tc.wantURL)
		}
	}
}

func TestSearch(t *testing.T) {
	c := parseFixture(t, "catalog.json")

	if got := len(c.Search("NLP corpus")); got != 1 {
		t.Errorf("Search matched %d entries, want 1", got)
	}

	if got := len(c.Search("xyzzy-not-found")); got != 0 {
		t.Errorf("Search matched %d entries, want 0", got)
	}

	results, err := c.SearchByRegex(`^urn:example:model:`)
	if err != nil || len(results) != 3 {
		t.Errorf("SearchByRegex = %d results, err %v, want 3", len(results), err)
	}
}

func TestResolveDisplayName(t *testing.T) {
	tests := []struct {
		entry CatalogEntry
		want  string
	}{
		{CatalogEntry{DisplayName: "Weather", Identifier: "urn:air:example.com:mcp:weather"}, "Weather"},
		{CatalogEntry{Identifier: "urn:air:example.com:mcp:weather"}, "weather"},
		{CatalogEntry{Identifier: "https://example.com/agents/research"}, "research"},
	}

	for _, tc := range tests {
		if got := tc.entry.ResolveDisplayName(); got != tc.want {
			t.Errorf("ResolveDisplayName(%+v) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}

// A manifest keeps the bytes it was decoded from, for signature checks.
func TestTrustManifest_Raw(t *testing.T) {
	published := manifestShape(t, "whitespace and member order")

	var manifest TrustManifest
	if err := json.Unmarshal(published, &manifest); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !bytes.Equal(manifest.Raw(), published) {
		t.Fatalf("Raw = %q, want %q", manifest.Raw(), published)
	}

	manifest.Raw()[0] = 'X'

	if !bytes.Equal(manifest.Raw(), published) {
		t.Error("Raw must return a copy")
	}

	// Decoding into a manifest that already holds data merges members, so the
	// bytes no longer describe a single source.
	if err := json.Unmarshal([]byte(`{"issuedAt":"2026-01-01T00:00:00Z"}`), &manifest); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if manifest.Raw() != nil {
		t.Errorf("a merged manifest must not claim a single source: %s", manifest.Raw())
	}

	if (&TrustManifest{Identity: "urn:example:a"}).Raw() != nil {
		t.Error("a manifest built in code has no raw bytes")
	}
}
