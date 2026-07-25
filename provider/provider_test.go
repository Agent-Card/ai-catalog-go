// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
	"github.com/agntcy/ai-catalog-go-sdk/internal/fixture"
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
