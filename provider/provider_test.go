// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

const (
	mcpType = "application/mcp-server-card+json"
	a2aType = "application/a2a-agent-card+json"

	leafAID = "urn:example:mcp:a"
	leafBID = "urn:example:a2a:b"
	leafCID = "urn:example:mcp:c"
	leafDID = "urn:example:a2a:d"

	nestedURL = "https://example.com/nested.json"
)

// stubFetcher serves documents from an in-memory map, recording call counts so
// tests can assert cycle detection and depth limiting.
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

// treeCatalog is a root catalog with a leaf, an inline nested catalog (which
// itself nests a grandchild), and a URL-referenced nested catalog.
func treeCatalog() []byte {
	return []byte(`{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "` + leafAID + `", "type": "` + mcpType + `", "url": "https://example.com/a.json"},
			{
				"identifier": "urn:example:catalog:inline",
				"type": "` + catalog.MediaTypeCatalog + `",
				"data": {
					"specVersion": "1.0",
					"entries": [
						{"identifier": "` + leafBID + `", "type": "` + a2aType + `", "description": "beta corpus", "url": "https://example.com/b.json"},
						{
							"identifier": "urn:example:catalog:grandchild",
							"type": "` + catalog.MediaTypeCatalog + `",
							"data": {
								"specVersion": "1.0",
								"entries": [
									{"identifier": "` + leafDID + `", "type": "` + a2aType + `", "url": "https://example.com/d.json"}
								]
							}
						}
					]
				}
			},
			{"identifier": "urn:example:catalog:remote", "type": "` + catalog.MediaTypeCatalog + `", "url": "` + nestedURL + `"}
		]
	}`)
}

func remoteNestedCatalog() []byte {
	return []byte(`{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "` + leafCID + `", "type": "` + mcpType + `", "url": "https://example.com/c.json"}
		]
	}`)
}

func newTreeCatalog(t *testing.T, opts ...Option) catalog.Source {
	t.Helper()

	root, err := catalog.Parse(treeCatalog())
	if err != nil {
		t.Fatalf("parse root catalog: %v", err)
	}

	fetcher := &stubFetcher{docs: map[string][]byte{nestedURL: remoteNestedCatalog()}}
	opts = append([]Option{WithFetcher(fetcher)}, opts...)

	c, err := FromCatalog(context.Background(), root, opts...)
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}

	return c
}

func TestCatalog_GetByID_AcrossNestedCatalogs(t *testing.T) {
	c := newTreeCatalog(t)
	ctx := context.Background()

	for _, id := range []string{leafAID, leafBID, leafCID, leafDID} {
		entry, err := c.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("GetByID(%q): unexpected error: %v", id, err)
		}

		if entry.Identifier != id {
			t.Fatalf("GetByID(%q): got identifier %q", id, entry.Identifier)
		}
	}
}

func TestCatalog_GetByID_NotFound(t *testing.T) {
	c := newTreeCatalog(t)

	_, err := c.GetByID(context.Background(), "urn:example:missing")
	if !errors.Is(err, catalog.ErrEntryNotFound) {
		t.Fatalf("expected ErrEntryNotFound, got %v", err)
	}
}

func TestCatalog_GetByType(t *testing.T) {
	c := newTreeCatalog(t)

	got, err := c.GetByType(context.Background(), mcpType)
	if err != nil {
		t.Fatalf("GetByType: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 MCP entries (leaf A + remote leaf C), got %d", len(got))
	}
}

func TestWellKnown(t *testing.T) {
	const domain = "acme-corp.com"

	url := "https://" + domain + catalog.WellKnownPath
	doc := []byte(`{"specVersion":"1.0","entries":[{"identifier":"` + leafAID +
		`","type":"` + mcpType + `","url":"https://example.com/a.json"}]}`)

	for _, input := range []string{domain, "https://" + domain, domain + "/"} {
		fetcher := &stubFetcher{docs: map[string][]byte{url: doc}}

		c, err := WellKnown(context.Background(), input, WithFetcher(fetcher))
		if err != nil {
			t.Fatalf("WellKnown(%q): %v", input, err)
		}

		if _, err := c.GetByID(context.Background(), leafAID); err != nil {
			t.Fatalf("WellKnown(%q): GetByID: %v", input, err)
		}
	}

	if _, err := WellKnown(context.Background(), "   "); err == nil {
		t.Fatal("WellKnown(empty domain): expected error")
	}
}

func TestCatalog_Search_DescendsIntoNested(t *testing.T) {
	c := newTreeCatalog(t)

	got, err := c.Search(context.Background(), "corpus")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	if len(got) != 1 || got[0].Identifier != leafBID {
		t.Fatalf("expected only leaf B to match 'corpus', got %+v", got)
	}
}

func TestCatalog_MaxDepthLimitsResolution(t *testing.T) {
	// With depth 1 only the root's direct children are expanded: the inline
	// child (with leaf B) and the remote child (with leaf C) are reachable, but
	// the grandchild (leaf D) nested inside the inline child is not.
	c := newTreeCatalog(t, WithMaxDepth(1))
	ctx := context.Background()

	if _, err := c.GetByID(ctx, leafBID); err != nil {
		t.Fatalf("leaf B should be reachable at depth 1: %v", err)
	}

	if _, err := c.GetByID(ctx, leafCID); err != nil {
		t.Fatalf("leaf C should be reachable at depth 1: %v", err)
	}

	if _, err := c.GetByID(ctx, leafDID); !errors.Is(err, catalog.ErrEntryNotFound) {
		t.Fatalf("leaf D should NOT be reachable at depth 1, got err=%v", err)
	}
}

func TestCatalog_CycleDetection(t *testing.T) {
	root, err := catalog.Parse([]byte(`{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:catalog:self", "type": "` + catalog.MediaTypeCatalog + `", "url": "` + nestedURL + `"}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// The fetched document references itself, which must not loop forever.
	selfDoc := []byte(`{
		"specVersion": "1.0",
		"entries": [
			{"identifier": "urn:example:catalog:self", "type": "` + catalog.MediaTypeCatalog + `", "url": "` + nestedURL + `"}
		]
	}`)
	fetcher := &stubFetcher{docs: map[string][]byte{nestedURL: selfDoc}}

	if _, err := FromCatalog(context.Background(), root, WithFetcher(fetcher)); err != nil {
		t.Fatalf("build with cyclic references should succeed: %v", err)
	}

	if fetcher.calls != 1 {
		t.Fatalf("expected the self-referencing URL to be fetched exactly once, got %d", fetcher.calls)
	}
}

func TestJSON_ResolvesRemoteNested(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")

	if err := os.WriteFile(path, treeCatalog(), 0o600); err != nil {
		t.Fatalf("write temp catalog: %v", err)
	}

	fetcher := &stubFetcher{docs: map[string][]byte{nestedURL: remoteNestedCatalog()}}

	c, err := JSON(context.Background(), path, WithFetcher(fetcher))
	if err != nil {
		t.Fatalf("JSON catalog: %v", err)
	}

	if _, err := c.GetByID(context.Background(), leafCID); err != nil {
		t.Fatalf("remote nested leaf C should be reachable from file catalog: %v", err)
	}
}

func TestWeb_LoadsRootViaFetcher(t *testing.T) {
	fetcher := &stubFetcher{docs: map[string][]byte{
		"https://host.example/.well-known/ai-catalog.json": treeCatalog(),
		nestedURL: remoteNestedCatalog(),
	}}

	c, err := Web(context.Background(), "https://host.example/.well-known/ai-catalog.json", WithFetcher(fetcher))
	if err != nil {
		t.Fatalf("Web catalog: %v", err)
	}

	if _, err := c.GetByID(context.Background(), leafAID); err != nil {
		t.Fatalf("root leaf A should be reachable: %v", err)
	}

	if _, err := c.GetByID(context.Background(), leafCID); err != nil {
		t.Fatalf("remote nested leaf C should be reachable: %v", err)
	}
}

func TestCatalog_ContextCancellation(t *testing.T) {
	c := newTreeCatalog(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.GetByID(ctx, leafAID); err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestFromCatalog_NilCatalog(t *testing.T) {
	if _, err := FromCatalog(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil catalog")
	}
}
