// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
)

// Identifiers known to exist in the shared fixture.
const (
	entryAID = "urn:example:agent:finance-v1"
	entryBID = "urn:example:data:nlp-corpus"
)

// stubFetcher serves documents from an in-memory map, recording call counts.
type stubFetcher struct {
	docs  map[string][]byte
	calls int
}

func (s *stubFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	s.calls++

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("stub fetch cancelled: %w", err)
	}

	data, ok := s.docs[url]
	if !ok {
		return nil, fmt.Errorf("stub: no document at %q", url)
	}

	return data, nil
}

func rootCatalog() []byte {
	return fixture.CatalogJSON
}

// loadDoc loads a Source into its in-memory document, failing the test on error.
func loadDoc(t *testing.T, c catalog.Source) *catalog.AICatalog {
	t.Helper()

	doc, err := c.Load(context.Background())
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	return doc
}

func TestJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	if err := os.WriteFile(path, rootCatalog(), 0o600); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	c, err := JSON(path)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	if _, ok := loadDoc(t, c).GetByID(entryBID); !ok {
		t.Fatalf("expected to find %q", entryBID)
	}
}

func TestJSON_MissingFile(t *testing.T) {
	if _, err := JSON(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestWeb_LoadsViaFetcher(t *testing.T) {
	const url = "https://host.example/catalog.json"

	fetcher := &stubFetcher{docs: map[string][]byte{url: rootCatalog()}}

	c, err := Web(context.Background(), url, WithFetcher(fetcher))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	if _, ok := loadDoc(t, c).GetByID(entryAID); !ok {
		t.Fatalf("expected to find %q", entryAID)
	}

	if fetcher.calls != 1 {
		t.Fatalf("expected exactly 1 fetch, got %d", fetcher.calls)
	}
}

// The default Fetcher is the transport every caller of Web gets unless they
// override it.
func TestWeb_DefaultHTTPFetcher(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/catalog.json" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", catalog.MediaTypeCatalog)
		_, _ = w.Write(rootCatalog())
	}))
	defer server.Close()

	c, err := Web(context.Background(), server.URL+"/catalog.json",
		WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	if _, ok := loadDoc(t, c).GetByID(entryAID); !ok {
		t.Fatalf("expected to find %q", entryAID)
	}

	if _, err := Web(context.Background(), server.URL+"/missing.json"); err == nil {
		t.Error("expected an error for a non-200 response")
	}
}

func TestLoad_ReturnsIndependentDocuments(t *testing.T) {
	const url = "https://host.example/catalog.json"

	fetcher := &stubFetcher{docs: map[string][]byte{url: rootCatalog()}}

	c, err := Web(context.Background(), url, WithFetcher(fetcher))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	first := loadDoc(t, c)
	second := loadDoc(t, c)

	if first == second {
		t.Fatal("each Load should return a distinct document, got the same pointer")
	}

	// Mutating one document must not leak into any later Load.
	first.Entries = append(first.Entries, catalog.CatalogEntry{Identifier: "urn:mutated"})
	first.Entries[0].DisplayName = "Mutated"

	third := loadDoc(t, c)

	if _, ok := third.GetByID("urn:mutated"); ok {
		t.Error("appended entry leaked into a later Load")
	}

	if third.Entries[0].DisplayName == "Mutated" {
		t.Error("field mutation leaked into a later Load")
	}
}

func TestRaw_PreservesServedBytes(t *testing.T) {
	const url = "https://host.example/catalog.json"

	// A member this SDK does not model: re-serializing the parsed document
	// would drop it, breaking any signature computed over the original.
	served := []byte(`{"specVersion":"1.0","entries":[],"futureMember":{"a":1}}`)

	c, err := Web(context.Background(), url,
		WithFetcher(&stubFetcher{docs: map[string][]byte{url: served}}))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	source, ok := c.(catalog.RawSource)
	if !ok {
		t.Fatal("built-in providers should implement catalog.RawSource")
	}

	raw, err := source.Raw(context.Background())
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}

	if !bytes.Equal(raw, served) {
		t.Errorf("Raw = %s, want %s", raw, served)
	}

	// The returned slice is the caller's to modify.
	raw[0] = 'X'

	again, err := source.Raw(context.Background())
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}

	if !bytes.Equal(again, served) {
		t.Errorf("mutating a returned slice changed the source: %s", again)
	}
}

func TestWeb_ContextCancellation(t *testing.T) {
	const url = "https://host.example/catalog.json"

	fetcher := &stubFetcher{docs: map[string][]byte{url: rootCatalog()}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Web(ctx, url, WithFetcher(fetcher)); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestLoad_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	if err := os.WriteFile(path, rootCatalog(), 0o600); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	c, err := JSON(path)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Load(ctx); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
