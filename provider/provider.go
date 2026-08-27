// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

// Package provider offers built-in ways to obtain a catalog.Source: a local
// JSON file (JSON) or an HTTP endpoint (Web). Both return the document as
// served; nested catalog entries are left unresolved for the caller to follow.
package provider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

// maxResponseBytes caps a document read by the default Fetcher.
const maxResponseBytes = 10 << 20 // 10 MiB

// defaultHTTPTimeout bounds a fetch so an unresponsive server cannot stall the
// caller indefinitely.
const defaultHTTPTimeout = 60 * time.Second

// defaultHTTPClient is used when no *http.Client is configured. Unlike
// http.DefaultClient it sets a timeout.
var defaultHTTPClient = &http.Client{Timeout: defaultHTTPTimeout}

// Fetcher retrieves the raw bytes of the document at url. Implement it to plug
// in a custom client, authentication, or caching.
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

// resolvedSource is a catalog.Source holding the document exactly as served.
// Load re-parses those bytes on every call, so each caller owns its document and
// the retained bytes stay valid for signature verification. Safe for concurrent
// use.
type resolvedSource struct {
	data []byte
}

var _ catalog.RawSource = (*resolvedSource)(nil)

// newResolvedSource retains data once it is known to parse.
func newResolvedSource(data []byte) (*resolvedSource, error) {
	if _, err := catalog.Parse(data); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}

	return &resolvedSource{data: data}, nil
}

// JSON creates a catalog.Source from a local AI Catalog JSON file.
func JSON(path string) (catalog.Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}

	source, err := newResolvedSource(data)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return source, nil
}

// Web creates a catalog.Source from an AI Catalog served at url, retrieved via
// the configured Fetcher (HTTP by default).
func Web(ctx context.Context, url string, opts ...Option) (catalog.Source, error) {
	cfg := newConfig(opts...)

	data, err := cfg.fetcher.Fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	source, err := newResolvedSource(data)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return source, nil
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

func (p *resolvedSource) Raw(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	return bytes.Clone(p.data), nil
}
