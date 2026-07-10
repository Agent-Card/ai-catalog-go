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
	"testing"
	"time"
)

const (
	testSpecVersion = "1.0.0"
	testEntryAlpha  = "agent-alpha"
)

var validCatalogJSON = []byte(`{
	"specVersion": "1.0.0",
	"host": {
		"displayName": "Acme Corp",
		"identifier": "acme-corp",
		"documentationURL": "https://example.com/docs"
	},
	"entries": [
		{
			"identifier": "agent-alpha",
			"displayName": "Alpha Agent",
			"mediaType": "application/json",
			"description": "An agent for alpha tasks",
			"tags": ["alpha", "automation"],
			"url": "https://example.com/agents/alpha"
		},
		{
			"identifier": "agent-beta",
			"displayName": "Beta Agent",
			"mediaType": "application/json",
			"description": "An agent for beta workflows",
			"tags": ["beta", "workflow"],
			"url": "https://example.com/agents/beta"
		}
	]
}`)

func validCatalog() *AICatalog {
	c, _ := FromJSON(validCatalogJSON)

	return c
}

func TestFromJSON_Valid(t *testing.T) {
	c, err := FromJSON(validCatalogJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q, want %q", c.SpecVersion, testSpecVersion)
	}

	if c.Host.Identifier != "acme-corp" {
		t.Errorf("Host.Identifier = %q, want %q", c.Host.Identifier, "acme-corp")
	}

	if len(c.Entries) != 2 {
		t.Errorf("len(Entries) = %d, want 2", len(c.Entries))
	}
}

func TestFromJSON_InvalidJSON(t *testing.T) {
	_, err := FromJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestMarshalToJSON_RoundTrip(t *testing.T) {
	original := validCatalog()

	data, err := original.MarshalToJSON()
	if err != nil {
		t.Fatalf("MarshalToJSON error: %v", err)
	}

	restored, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON error after round-trip: %v", err)
	}

	if restored.SpecVersion != original.SpecVersion {
		t.Errorf("SpecVersion mismatch: got %q, want %q", restored.SpecVersion, original.SpecVersion)
	}

	if restored.Host.Identifier != original.Host.Identifier {
		t.Errorf("Host.Identifier mismatch: got %q, want %q", restored.Host.Identifier, original.Host.Identifier)
	}

	if len(restored.Entries) != len(original.Entries) {
		t.Errorf("entry count mismatch: got %d, want %d", len(restored.Entries), len(original.Entries))
	}

	for i, e := range restored.Entries {
		if e.Identifier != original.Entries[i].Identifier {
			t.Errorf("entry[%d].Identifier: got %q, want %q", i, e.Identifier, original.Entries[i].Identifier)
		}
	}
}

func TestMarshalToJSON_ValidJSON(t *testing.T) {
	c := validCatalog()

	data, err := c.MarshalToJSON()
	if err != nil {
		t.Fatalf("MarshalToJSON error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}

func TestFromFile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	if err := os.WriteFile(path, validCatalogJSON, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	c, err := FromFile(path)
	if err != nil {
		t.Fatalf("FromFile error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q, want %q", c.SpecVersion, testSpecVersion)
	}
}

func TestFromFile_NotFound(t *testing.T) {
	_, err := FromFile("/nonexistent/path/catalog.json")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(path, []byte(`{bad}`), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := FromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestFromURL_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validCatalogJSON)
	}))
	defer srv.Close()

	c, err := FromURL(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FromURL error: %v", err)
	}

	if c.SpecVersion != testSpecVersion {
		t.Errorf("SpecVersion = %q, want %q", c.SpecVersion, testSpecVersion)
	}
}

func TestFromURL_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := FromURL(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

func TestFromURL_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	_, err := FromURL(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON body, got nil")
	}
}

func TestSearch_KeywordMatch(t *testing.T) {
	c := validCatalog()

	results := c.Search("alpha")
	if len(results) != 1 {
		t.Fatalf("Search(alpha): got %d results, want 1", len(results))
	}

	if results[0].Identifier != testEntryAlpha {
		t.Errorf("unexpected result: %q", results[0].Identifier)
	}
}

func TestSearch_TagMatch(t *testing.T) {
	c := validCatalog()

	results := c.Search("workflow")
	if len(results) != 1 {
		t.Fatalf("Search(workflow): got %d results, want 1", len(results))
	}

	if results[0].Identifier != "agent-beta" {
		t.Errorf("unexpected result: %q", results[0].Identifier)
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	c := validCatalog()

	results := c.Search("ALPHA")
	if len(results) != 1 {
		t.Fatalf("Search(ALPHA): got %d results, want 1", len(results))
	}
}

func TestSearch_RegexMatch(t *testing.T) {
	c := validCatalog()

	results := c.Search("agent-(alpha|beta)")
	if len(results) != 2 {
		t.Fatalf("Search regex: got %d results, want 2", len(results))
	}
}

func TestSearch_RegexPartialMatch(t *testing.T) {
	c := validCatalog()

	results := c.Search("^agent-a")
	if len(results) != 1 {
		t.Fatalf("Search(^agent-a): got %d results, want 1", len(results))
	}

	if results[0].Identifier != testEntryAlpha {
		t.Errorf("unexpected result: %q", results[0].Identifier)
	}
}

func TestSearch_NoMatch(t *testing.T) {
	c := validCatalog()

	results := c.Search("nonexistent")
	if len(results) != 0 {
		t.Errorf("Search(nonexistent): got %d results, want 0", len(results))
	}
}

func TestSearch_EmptyQuery(t *testing.T) {
	c := validCatalog()

	// Empty string matches every entry (it is a substring of everything).
	results := c.Search("")
	if len(results) != len(c.Entries) {
		t.Errorf("Search(''): got %d results, want %d", len(results), len(c.Entries))
	}
}

func TestGetById_Hit(t *testing.T) {
	c := validCatalog()

	entry, ok := c.GetById(testEntryAlpha)
	if !ok {
		t.Fatal("GetById(agent-alpha): expected hit, got miss")
	}

	if entry.Identifier != testEntryAlpha {
		t.Errorf("entry.Identifier = %q, want %q", entry.Identifier, testEntryAlpha)
	}
}

func TestGetById_Miss(t *testing.T) {
	c := validCatalog()

	_, ok := c.GetById("does-not-exist")
	if ok {
		t.Fatal("GetById(does-not-exist): expected miss, got hit")
	}
}

func TestGetById_ReturnsPointerIntoSlice(t *testing.T) {
	c := validCatalog()

	entry, ok := c.GetById("agent-beta")
	if !ok {
		t.Fatal("expected hit")
	}

	// Mutate via the pointer and confirm it is reflected in the catalog.
	entry.DisplayName = "Modified"

	if c.Entries[1].DisplayName != "Modified" {
		t.Error("GetById should return a pointer into the Entries slice")
	}
}

func TestValidate_ValidCatalog(t *testing.T) {
	c := validCatalog()

	if err := c.Validate(); err != nil {
		t.Errorf("Validate on valid catalog: unexpected error: %v", err)
	}
}

func TestValidate_EmptySpecVersion(t *testing.T) {
	c := validCatalog()
	c.SpecVersion = ""

	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for empty specVersion")
	}
}

func TestValidate_EmptyHostIdentifier(t *testing.T) {
	c := validCatalog()
	c.Host.Identifier = ""

	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for empty host.identifier")
	}
}

func TestValidate_EmptyMediaType(t *testing.T) {
	c := validCatalog()
	c.Entries[0].MediaType = ""

	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for entry with empty mediaType")
	}
}

func TestValidate_DuplicateIdentifier(t *testing.T) {
	c := validCatalog()
	c.Entries = append(c.Entries, Entry{
		Identifier: testEntryAlpha,
		MediaType:  "application/json",
		URL:        "https://example.com/dup",
	})

	if err := c.Validate(); err == nil {
		t.Error("Validate: expected error for duplicate entry identifier")
	}
}

func TestValidate_EmptyEntries(t *testing.T) {
	c := &AICatalog{
		SpecVersion: testSpecVersion,
		Host:        Host{Identifier: "acme-corp"},
		Entries:     []Entry{},
	}

	if err := c.Validate(); err != nil {
		t.Errorf("Validate with empty entries: unexpected error: %v", err)
	}
}

func TestEntryGetters(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
	e := &Entry{
		Identifier:  "id-1",
		DisplayName: "My Entry",
		MediaType:   "application/json",
		Description: "A test entry",
		Tags:        []string{"foo", "bar"},
		URL:         "https://example.com/entry",
		UpdatedAt:   &ts,
	}

	if e.GetIdentifier() != "id-1" {
		t.Errorf("GetIdentifier = %q", e.GetIdentifier())
	}

	if e.GetDisplayName() != "My Entry" {
		t.Errorf("GetDisplayName = %q", e.GetDisplayName())
	}

	if e.GetMediaType() != "application/json" {
		t.Errorf("GetMediaType = %q", e.GetMediaType())
	}

	if e.GetDescription() != "A test entry" {
		t.Errorf("GetDescription = %q", e.GetDescription())
	}

	if len(e.GetTags()) != 2 {
		t.Errorf("GetTags len = %d", len(e.GetTags()))
	}

	if e.GetURL() != "https://example.com/entry" {
		t.Errorf("GetURL = %q", e.GetURL())
	}

	if e.GetUpdatedAt() == nil || !e.GetUpdatedAt().Equal(ts) {
		t.Errorf("GetUpdatedAt = %v", e.GetUpdatedAt())
	}
}

func TestPull_Success(t *testing.T) {
	artifact := []byte(`{"name":"my-agent"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact)
	}))
	defer srv.Close()

	e := &Entry{
		Identifier: "test-entry",
		MediaType:  "application/json",
		URL:        srv.URL,
	}

	data, err := e.Pull(context.Background())
	if err != nil {
		t.Fatalf("Pull error: %v", err)
	}

	if string(data) != string(artifact) {
		t.Errorf("Pull data = %q, want %q", data, artifact)
	}
}

func TestPull_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()

	e := &Entry{
		Identifier: "test-entry",
		MediaType:  "application/json",
		URL:        srv.URL,
	}

	_, err := e.Pull(context.Background())
	if err == nil {
		t.Fatal("Pull: expected error for non-200 response, got nil")
	}
}

func TestPull_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := &Entry{
		Identifier: "test-entry",
		MediaType:  "application/json",
		URL:        srv.URL,
	}

	_, err := e.Pull(ctx)
	if err == nil {
		t.Fatal("Pull: expected error for cancelled context, got nil")
	}
}
