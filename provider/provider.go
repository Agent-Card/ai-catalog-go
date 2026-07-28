// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package provider offers built-in ways to obtain a catalog.Source from a
// concrete source — a local JSON file (JSON) or an HTTP endpoint (Web). Each
// returns the document as-is; nested catalog entries are left unresolved for the
// caller to follow as needed.
package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agntcy/ai-catalog-go-sdk/catalog"
)

// maxResponseBytes caps a document read by the default Fetcher.
const maxResponseBytes = 10 << 20 // 10 MiB

// defaultHTTPTimeout bounds a fetch by the default client, so a slow or
// unresponsive server cannot stall the caller indefinitely.
const defaultHTTPTimeout = 60 * time.Second

// defaultHTTPClient is used when no *http.Client is configured. Unlike
// http.DefaultClient it sets a timeout.
var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

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

// WithFetcher sets the Fetcher used by Web to retrieve documents.
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
		client = defaultHTTPClient
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

// resolvedSource is a catalog.Source backed by the serialized bytes of a
// validated document. Each Load re-parses them, so every caller receives an
// independent document it fully owns. Safe for concurrent use.
type resolvedSource struct {
	data []byte
}

var _ catalog.Source = (*resolvedSource)(nil)

// newResolvedSource captures c as bytes so that later Loads can hand back
// independent copies.
func newResolvedSource(c *catalog.AICatalog) (*resolvedSource, error) {
	data, err := c.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("serialize catalog: %w", err)
	}

	return &resolvedSource{data: data}, nil
}

// JSON creates a catalog.Source from a local AI Catalog JSON file.
func JSON(path string) (catalog.Source, error) {
	c, err := catalog.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return newResolvedSource(c)
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

	return newResolvedSource(c)
}

func (p *resolvedSource) Load(ctx context.Context) (*catalog.AICatalog, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	doc, err := catalog.Parse(p.data)
	if err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	return doc, nil
}
