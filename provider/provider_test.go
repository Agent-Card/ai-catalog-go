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
)

const (
	mcpType = "application/mcp-server-card+json"

	leafAID = "urn:example:mcp:a"
	leafBID = "urn:example:a2a:b"
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
	return []byte(`{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "` + leafAID + `", "type": "` + mcpType + `", "url": "https://example.com/a.json"},
			{"identifier": "` + leafBID + `", "type": "` + mcpType + `", "url": "https://example.com/b.json"}
		]
	}`)
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

func TestFromCatalog(t *testing.T) {
	root, err := catalog.Parse(rootCatalog())
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	c, err := FromCatalog(root)
	if err != nil {
		t.Fatalf("FromCatalog: %v", err)
	}

	doc := loadDoc(t, c)
	if len(doc.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(doc.Entries))
	}

	if _, ok := doc.GetByID(leafAID); !ok {
		t.Fatalf("expected to find %q", leafAID)
	}
}

func TestFromCatalog_NilCatalog(t *testing.T) {
	if _, err := FromCatalog(nil); err == nil {
		t.Fatal("expected error for nil catalog")
	}
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

	if _, ok := loadDoc(t, c).GetByID(leafBID); !ok {
		t.Fatalf("expected to find %q", leafBID)
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

	if _, ok := loadDoc(t, c).GetByID(leafAID); !ok {
		t.Fatalf("expected to find %q", leafAID)
	}

	if fetcher.calls != 1 {
		t.Fatalf("expected exactly 1 fetch, got %d", fetcher.calls)
	}
}

func TestWellKnown(t *testing.T) {
	const domain = "acme-corp.com"

	url := "https://" + domain + catalog.WellKnownPath

	for _, input := range []string{domain, "https://" + domain, domain + "/"} {
		fetcher := &stubFetcher{docs: map[string][]byte{url: rootCatalog()}}

		c, err := WellKnown(context.Background(), input, WithFetcher(fetcher))
		if err != nil {
			t.Fatalf("WellKnown(%q): %v", input, err)
		}

		if _, ok := loadDoc(t, c).GetByID(leafAID); !ok {
			t.Fatalf("WellKnown(%q): expected to find %q", input, leafAID)
		}
	}

	if _, err := WellKnown(context.Background(), "   "); err == nil {
		t.Fatal("WellKnown(empty domain): expected error")
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
	root, err := catalog.Parse(rootCatalog())
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	c, err := FromCatalog(root)
	if err != nil {
		t.Fatalf("FromCatalog: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.Load(ctx); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
