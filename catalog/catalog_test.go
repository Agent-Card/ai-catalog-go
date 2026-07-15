// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSpecVersion = "1.0"
	financeID       = "urn:example:agent:finance-v1"
	nlpID           = "urn:example:data:nlp-corpus"
	embeddingID     = "urn:example:model:embedding-v2"
)

var validCatalogJSON = []byte(`{
	"specVersion": "1.0",
	"host": {
		"displayName": "Acme Corp",
		"identifier": "did:example:org-acme-corp",
		"documentationUrl": "https://example.com/docs"
	},
	"entries": [
		{
			"identifier": "urn:example:agent:finance-v1",
			"displayName": "Finance Agent",
			"type": "application/a2a-agent-card+json",
			"description": "Handles financial queries",
			"tags": ["finance", "banking"],
			"url": "https://example.com/finance.json"
		},
		{
			"identifier": "urn:example:data:nlp-corpus",
			"displayName": "NLP Corpus",
			"type": "application/octet-stream",
			"description": "Large language model training data",
			"tags": ["nlp", "dataset"],
			"url": "https://example.com/nlp.bin"
		},
		{
			"identifier": "urn:example:model:embedding-v2",
			"type": "application/gguf",
			"url": "https://example.com/embed.gguf"
		}
	]
}`)

func validCatalog(t *testing.T) *AICatalog {
	t.Helper()

	c, err := Parse(validCatalogJSON)
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

	if len(c.Entries) != 3 {
		t.Fatalf("len(Entries) = %d, want 3", len(c.Entries))
	}

	if c.Entries[0].Type != "application/a2a-agent-card+json" {
		t.Errorf("entry[0].Type = %q", c.Entries[0].Type)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestParseString(t *testing.T) {
	c, err := ParseString(string(validCatalogJSON))
	if err != nil {
		t.Fatalf("ParseString error: %v", err)
	}

	if len(c.Entries) != 3 {
		t.Errorf("len(Entries) = %d, want 3", len(c.Entries))
	}
}

func TestParseReader(t *testing.T) {
	c, err := ParseReader(strings.NewReader(string(validCatalogJSON)))
	if err != nil {
		t.Fatalf("ParseReader error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q", c.SpecVersion)
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

func TestToJSONIndent(t *testing.T) {
	c := validCatalog(t)

	data, err := c.ToJSONIndent()
	if err != nil {
		t.Fatalf("ToJSONIndent error: %v", err)
	}

	if !strings.Contains(string(data), "\n") {
		t.Error("indented JSON should contain newlines")
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("indented output is not valid JSON: %v", err)
	}
}

func TestWriteJSON(t *testing.T) {
	c := validCatalog(t)

	var buf strings.Builder
	if err := c.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	if _, err := ParseString(buf.String()); err != nil {
		t.Fatalf("written JSON should parse: %v", err)
	}
}

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	if err := os.WriteFile(path, validCatalogJSON, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	c, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q", c.SpecVersion)
	}
}

func TestParseFile_NotFound(t *testing.T) {
	if _, err := ParseFile("/nonexistent/path/catalog.json"); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestFromURL_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validCatalogJSON)
	}))
	defer srv.Close()

	c, err := FromURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FromURL error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q", c.SpecVersion)
	}
}

func TestFromURL_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := FromURL(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error for non-200 response, got nil")
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

	entry.DisplayName = "Modified"

	if c.Entries[1].DisplayName != "Modified" {
		t.Error("GetByID should return a pointer into the Entries slice")
	}
}

func TestSearch(t *testing.T) {
	c := validCatalog(t)

	cases := []struct {
		query string
		want  int
	}{
		{"nlp-corpus", 1},
		{"FINANCE", 1},
		{"NLP Corpus", 1},
		{"financial queries", 1},
		{"dataset", 1},
		{"urn:example", 3},
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

	anchored, err := c.SearchByRegex(`^urn:example:model:`)
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

func TestIsNestedCatalog(t *testing.T) {
	nested := &CatalogEntry{Type: MediaTypeCatalog}
	if !nested.IsNestedCatalog() {
		t.Error("expected IsNestedCatalog to be true")
	}

	leaf := &CatalogEntry{Type: "application/json"}
	if leaf.IsNestedCatalog() {
		t.Error("expected IsNestedCatalog to be false")
	}
}

func TestPull_Success(t *testing.T) {
	artifact := []byte(`{"name":"my-agent"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer srv.Close()

	e := &CatalogEntry{Identifier: "test", Type: "application/json", URL: srv.URL}

	data, err := e.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull error: %v", err)
	}

	if string(data) != string(artifact) {
		t.Errorf("Pull data = %q, want %q", data, artifact)
	}
}

func TestPull_NoURL(t *testing.T) {
	e := &CatalogEntry{Identifier: "test", Type: MediaTypeCatalog, Data: json.RawMessage(`{}`)}

	if _, err := e.Pull(context.Background()); err == nil {
		t.Fatal("expected error when pulling an entry with no url")
	}
}

func TestPull_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	e := &CatalogEntry{Identifier: "test", Type: "application/json", URL: srv.URL}

	if _, err := e.Pull(context.Background()); err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}
