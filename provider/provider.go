// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package provider offers built-in ways to obtain a catalog.Source from a
// concrete source — a local JSON file (JSON), a remote/well-known HTTP endpoint
// (Web), or an already-parsed document (FromCatalog). Each loader resolves
// nested catalogs (inline and URL-referenced) up to a bounded depth.
package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

// DefaultMaxDepth is the default maximum nesting depth to which built-in
// providers resolve nested catalogs. It matches the depth limit recommended by
// the AI Catalog specification.
const DefaultMaxDepth = 4

// maxResponseBytes caps the size of a document read by the default Fetcher to
// bound memory use on untrusted input.
const maxResponseBytes = 10 << 20 // 10 MiB

// Fetcher retrieves the raw bytes of a document at url. It abstracts the
// transport used to load a catalog and resolve URL-referenced nested catalogs
// so callers can plug in custom HTTP clients, authentication, caching, or
// offline resolvers.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// Option configures a built-in provider.
type Option func(*config)

type config struct {
	fetcher  Fetcher
	maxDepth int
}

// WithFetcher sets the Fetcher used to resolve URL-referenced nested catalogs
// (and, for Web, the root document).
func WithFetcher(f Fetcher) Option {
	return func(c *config) {
		if f != nil {
			c.fetcher = f
		}
	}
}

// WithHTTPClient sets the *http.Client used by the default Fetcher. It is a
// convenience wrapper around WithFetcher.
func WithHTTPClient(client *http.Client) Option {
	return WithFetcher(&httpFetcher{client: client})
}

// WithMaxDepth sets the maximum nesting depth to which nested catalogs are
// resolved. Values below 1 are ignored.
func WithMaxDepth(depth int) Option {
	return func(c *config) {
		if depth >= 1 {
			c.maxDepth = depth
		}
	}
}

func newConfig(opts ...Option) config {
	cfg := config{
		fetcher:  &httpFetcher{},
		maxDepth: DefaultMaxDepth,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// httpFetcher is the default Fetcher, backed by an *http.Client.
type httpFetcher struct {
	client *http.Client
}

func (h *httpFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	client := h.client
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", url, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %q: unexpected status code %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", url, err)
	}

	return data, nil
}

// resolvedSource is a catalog.Source backed by a tree that has been fully
// resolved (all reachable nested catalogs fetched/parsed) at construction time.
// It is safe for concurrent use because it is read-only after construction.
type resolvedSource struct {
	root     *catalog.AICatalog
	catalogs []*catalog.AICatalog // root first, then every resolved nested catalog
}

var _ catalog.Source = (*resolvedSource)(nil)

// FromCatalog wraps an already-parsed AI Catalog as a catalog.Source,
// resolving any nested catalogs it references (inline data, and URLs via the
// configured Fetcher) up to the configured depth.
func FromCatalog(ctx context.Context, c *catalog.AICatalog, opts ...Option) (catalog.Source, error) {
	if c == nil {
		return nil, errors.New("catalog is nil")
	}

	return build(ctx, c, "", newConfig(opts...))
}

// JSON creates a catalog.Source from a local AI Catalog JSON file.
// URL-referenced nested catalogs are resolved via the configured Fetcher (HTTP
// by default).
func JSON(ctx context.Context, path string, opts ...Option) (catalog.Source, error) {
	c, err := catalog.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return build(ctx, c, "file://"+path, newConfig(opts...))
}

// Web creates a catalog.Source from an AI Catalog served at url (for example a
// host's "/.well-known/ai-catalog.json"). The root document and any
// URL-referenced nested catalogs are retrieved via the configured Fetcher.
func Web(ctx context.Context, url string, opts ...Option) (catalog.Source, error) {
	cfg := newConfig(opts...)

	data, err := cfg.fetcher.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	c, err := catalog.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	return build(ctx, c, url, cfg)
}

// WellKnown creates a catalog.Source from the AI Catalog served at the spec's
// well-known URI for domain — "https://{domain}/.well-known/ai-catalog.json" —
// which is the conventional entry point for domain-level discovery. domain is a
// bare host (any leading scheme and trailing slash are trimmed); the fetch and
// nested-catalog resolution are performed exactly as by Web.
func WellKnown(ctx context.Context, domain string, opts ...Option) (catalog.Source, error) {
	host := strings.TrimSpace(domain)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")

	if host == "" {
		return nil, errors.New("domain is empty")
	}

	return Web(ctx, "https://"+host+catalog.WellKnownPath, opts...)
}

// build resolves the catalog tree rooted at root and returns a ready
// catalog.Source. rootKey identifies the root source for cycle detection; it
// may be empty.
func build(ctx context.Context, root *catalog.AICatalog, rootKey string, cfg config) (catalog.Source, error) {
	r := &resolver{
		fetcher:  cfg.fetcher,
		maxDepth: cfg.maxDepth,
		visited:  make(map[string]bool),
	}
	if rootKey != "" {
		r.visited[rootKey] = true
	}

	if err := r.walk(ctx, root, 0); err != nil {
		return nil, err
	}

	return &resolvedSource{root: root, catalogs: r.catalogs}, nil
}

// resolver performs a depth-limited, cycle-safe traversal of a catalog tree,
// collecting every reachable catalog. Nested catalogs that cannot be fetched or
// parsed are skipped (best-effort resolution); only context cancellation aborts
// the traversal.
type resolver struct {
	fetcher  Fetcher
	maxDepth int
	visited  map[string]bool
	catalogs []*catalog.AICatalog
}

func (r *resolver) walk(ctx context.Context, c *catalog.AICatalog, depth int) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("resolve catalog: %w", err)
	}

	r.catalogs = append(r.catalogs, c)

	if depth >= r.maxDepth {
		return nil
	}

	for i := range c.Entries {
		entry := &c.Entries[i]
		if !entry.IsNestedCatalog() {
			continue
		}

		nested := r.resolveNested(ctx, entry)
		if nested == nil {
			continue
		}

		if err := r.walk(ctx, nested, depth+1); err != nil {
			return err
		}
	}

	return nil
}

// resolveNested returns the nested catalog referenced by entry, or nil if it is
// absent, already visited, or cannot be fetched/parsed.
func (r *resolver) resolveNested(ctx context.Context, entry *catalog.CatalogEntry) *catalog.AICatalog {
	switch {
	case entry.URL != "":
		if r.visited[entry.URL] {
			return nil
		}

		r.visited[entry.URL] = true

		data, err := r.fetcher.Fetch(ctx, entry.URL)
		if err != nil {
			return nil
		}

		nested, err := catalog.Parse(data)
		if err != nil {
			return nil
		}

		return nested

	case len(entry.Data) > 0:
		key := "inline:" + entry.Identifier
		if r.visited[key] {
			return nil
		}

		r.visited[key] = true

		nested, err := catalog.Parse(entry.Data)
		if err != nil {
			return nil
		}

		return nested

	default:
		return nil
	}
}

func (p *resolvedSource) Document(ctx context.Context) (*catalog.AICatalog, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}

	return p.root, nil
}

func (p *resolvedSource) GetByID(ctx context.Context, id string) (*catalog.CatalogEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("get by id: %w", err)
	}

	for _, c := range p.catalogs {
		if entry, ok := c.GetByID(id); ok {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("%w: %q", catalog.ErrEntryNotFound, id)
}

func (p *resolvedSource) GetByType(ctx context.Context, mediaType string) ([]*catalog.CatalogEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("get by type: %w", err)
	}

	var results []*catalog.CatalogEntry

	for _, c := range p.catalogs {
		results = append(results, c.GetByType(mediaType)...)
	}

	return results, nil
}

func (p *resolvedSource) Search(ctx context.Context, query string) ([]*catalog.CatalogEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("search: %w", err)
	}

	var results []*catalog.CatalogEntry

	for _, c := range p.catalogs {
		results = append(results, c.Search(query)...)
	}

	return results, nil
}
