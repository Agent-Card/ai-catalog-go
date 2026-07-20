// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package provider offers built-in ways to obtain a catalog.Source from a
// concrete source — a local JSON file (JSON), a remote/well-known HTTP endpoint
// (Web, WellKnown), or an already-parsed document (FromCatalog). Each returns
// the document as-is; nested catalog entries are left unresolved for the caller
// to follow as needed.
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

// maxResponseBytes caps a document read by the default Fetcher.
const maxResponseBytes = 10 << 20 // 10 MiB

// Fetcher retrieves the raw bytes of a document at url, abstracting the
// transport so callers can plug in custom clients, auth, or caching.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// Option configures a built-in provider.
type Option func(*config)

type config struct {
	fetcher Fetcher
}

// WithFetcher sets the Fetcher used by Web and WellKnown to retrieve documents.
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

func newConfig(opts ...Option) config {
	cfg := config{fetcher: &httpFetcher{}}

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

// resolvedSource is a catalog.Source backed by an already-loaded document. It is
// read-only and safe for concurrent use.
type resolvedSource struct {
	doc *catalog.AICatalog
}

var _ catalog.Source = (*resolvedSource)(nil)

// FromCatalog wraps an already-parsed AI Catalog as a catalog.Source.
func FromCatalog(c *catalog.AICatalog) (catalog.Source, error) {
	if c == nil {
		return nil, errors.New("catalog is nil")
	}

	return &resolvedSource{doc: c}, nil
}

// JSON creates a catalog.Source from a local AI Catalog JSON file.
func JSON(path string) (catalog.Source, error) {
	c, err := catalog.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return &resolvedSource{doc: c}, nil
}

// Web creates a catalog.Source from an AI Catalog served at url, retrieved via
// the configured Fetcher (HTTP by default).
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

	return &resolvedSource{doc: c}, nil
}

// WellKnown creates a catalog.Source from the AI Catalog served at
// "https://{domain}/.well-known/ai-catalog.json". domain is a bare host (any
// leading scheme and trailing slash are trimmed); retrieval behaves as Web.
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

func (p *resolvedSource) Load(ctx context.Context) (*catalog.AICatalog, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return p.doc, nil
}
