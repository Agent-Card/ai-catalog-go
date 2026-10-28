// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

// Package discovery finds the AI Catalog of a website or domain, following the
// discovery procedure of the specification (https://ai-catalog.io/spec/#discovery).
//
// Given a URL or a bare domain, Discover looks, in order, for
//
//  1. a catalog document at the URL itself,
//  2. a Link header with rel="ai-catalog",
//  3. a <link rel="ai-catalog"> element in an HTML document, and
//  4. a catalog at the well-known URI /.well-known/ai-catalog.json,
//
// and returns the first valid catalog. A link that leads nowhere does not stop
// the search. Nested catalogs are not followed.
//
// # Network behavior
//
// Only https is requested. Input with another scheme is rejected, and so are
// links to one. The default client refuses redirects to http, times out after 30
// seconds and reads at most 10 MiB per response.
//
// Discovery does not guard against requests to private addresses. A service
// that runs it for callers it does not trust must supply a Fetcher, or an
// *http.Client with a dialer, that checks where it connects.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

// schemeHTTPS is the only scheme discovery requests.
const schemeHTTPS = "https"

// LinkRelation is the link relation type that points to an AI Catalog (RFC 8288).
const LinkRelation = "ai-catalog"

// Method says how a catalog was found.
type Method string

const (
	// MethodDirect means the URL that was given is itself a catalog document.
	MethodDirect Method = "direct"

	// MethodLinkHeader means an ai-catalog relation in an HTTP Link header.
	MethodLinkHeader Method = "link-header"

	// MethodHTMLLink means an ai-catalog link element in an HTML document.
	MethodHTMLLink Method = "html-link"

	// MethodWellKnown means the well-known URI.
	MethodWellKnown Method = "well-known"
)

// Result is a catalog that was found.
type Result struct {
	// URL is where the catalog was served from, after redirects. Relative
	// references in the catalog resolve against it.
	URL string

	Method Method

	Catalog *catalog.AICatalog

	// Raw is the document as served. Signatures are verified against these
	// bytes, since a re-serialized Catalog drops what the SDK does not model.
	Raw []byte
}

var (
	// ErrInvalidInput is returned for input that is not an https URL or a domain.
	ErrInvalidInput = errors.New("invalid input")

	// ErrNotFound is returned, wrapped in a *NotFoundError, when no catalog was found.
	ErrNotFound = errors.New("no AI Catalog found")
)

// Attempt is a URL that was tried and did not lead to a catalog.
type Attempt struct {
	URL    string
	Method Method
	Reason string
}

// NotFoundError lists everything that was tried. It matches ErrNotFound.
type NotFoundError struct {
	Input    string
	Attempts []Attempt
}

func (e *NotFoundError) Error() string {
	var b strings.Builder

	fmt.Fprintf(&b, "no AI Catalog found for %q", e.Input)

	for _, a := range e.Attempts {
		fmt.Fprintf(&b, "\n  %s (%s): %s", a.URL, a.Method, a.Reason)
	}

	return b.String()
}

func (e *NotFoundError) Unwrap() error { return ErrNotFound }

// Option configures Discover.
type Option func(*config)

type config struct {
	fetcher Fetcher
}

// WithFetcher sets the Fetcher that performs the requests.
func WithFetcher(f Fetcher) Option {
	return func(c *config) {
		if f != nil {
			c.fetcher = f
		}
	}
}

// WithHTTPClient sets the *http.Client the default Fetcher uses. Its redirect
// policy and timeout are yours to set.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) {
		if client != nil {
			c.fetcher = httpFetcher{client: client}
		}
	}
}

// Discover finds the catalog of input, a URL or a bare domain (https is assumed).
func Discover(ctx context.Context, input string, opts ...Option) (*Result, error) {
	start, err := parseInput(input)
	if err != nil {
		return nil, err
	}

	cfg := config{fetcher: httpFetcher{client: defaultHTTPClient()}}
	for _, opt := range opts {
		opt(&cfg)
	}

	d := &discoverer{fetcher: cfg.fetcher, requested: map[string]bool{}}

	result, resp, err := d.try(ctx, start, MethodDirect)
	if err != nil || result != nil {
		return result, err
	}

	// The well-known URI is requested on the host that was asked for and, when a
	// redirect led elsewhere, on the host that was reached, which comes first.
	bases := []*url.URL{start}

	var candidates []candidate

	if resp != nil {
		if !sameOrigin(resp.URL, start) {
			bases = []*url.URL{resp.URL, start}
		}

		if resp.success() {
			candidates = linkCandidates(resp)
		}
	}

	for _, base := range bases {
		wellKnown := base.ResolveReference(&url.URL{Path: catalog.WellKnownPath})
		candidates = append(candidates, candidate{url: wellKnown, method: MethodWellKnown})
	}

	for _, c := range candidates {
		if c.url.Scheme != schemeHTTPS {
			d.fail(c.url, c.method, "not an https URL")

			continue
		}

		if result, _, err := d.try(ctx, c.url, c.method); err != nil || result != nil {
			return result, err
		}
	}

	return nil, &NotFoundError{Input: strings.TrimSpace(input), Attempts: d.attempts}
}

// candidate is a URL that may hold the catalog, and how it was found.
type candidate struct {
	url    *url.URL
	method Method
}

// discoverer holds the state of one Discover call.
type discoverer struct {
	fetcher   Fetcher
	requested map[string]bool
	attempts  []Attempt
}

// try requests u, unless it was requested already. It returns the catalog if u
// holds one; otherwise it records why not and returns the response, if any, for
// its links. It fails only when ctx is done.
func (d *discoverer) try(ctx context.Context, u *url.URL, method Method) (*Result, *Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("discover catalog: %w", err)
	}

	key := requestKey(u)
	if d.requested[key] {
		return nil, nil, nil
	}

	d.requested[key] = true

	resp, err := d.fetcher.Fetch(ctx, u)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("discover catalog: %w", ctxErr)
		}

		d.fail(u, method, err.Error())

		return nil, nil, nil
	}

	doc, err := asCatalog(resp)
	if err != nil {
		d.fail(resp.URL, method, err.Error())

		return nil, resp, nil
	}

	return &Result{URL: resp.URL.String(), Method: method, Catalog: doc, Raw: resp.Body}, resp, nil
}

func (d *discoverer) fail(u *url.URL, method Method, reason string) {
	d.attempts = append(d.attempts, Attempt{URL: u.String(), Method: method, Reason: reason})
}

func parseInput(input string) (*url.URL, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: the input is empty", ErrInvalidInput)
	}

	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", ErrInvalidInput, input, err)
	}

	if u.Scheme != schemeHTTPS {
		return nil, fmt.Errorf("%w: %q: only https URLs are supported, not %s", ErrInvalidInput, input, u.Scheme)
	}

	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: %q: the URL has no host", ErrInvalidInput, input)
	}

	// An empty path is a request for "/"; spell it out so URLs compare equal.
	if u.Path == "" {
		u.Path = "/"
	}

	return u, nil
}

// requestKey is the URL without its fragment, which is never sent to the server.
func requestKey(u *url.URL) string {
	c := *u
	c.Fragment = ""
	c.RawFragment = ""

	return c.String()
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host
}

// asCatalog accepts a response that succeeded and holds a JSON document with a
// specVersion. The media type is not checked, as the specification accepts any JSON type.
func asCatalog(resp *Response) (*catalog.AICatalog, error) {
	if !resp.success() {
		return nil, errors.New(describeStatus(resp.StatusCode))
	}

	doc, err := catalog.Parse(resp.Body)
	if err != nil {
		if resp.isHTML() {
			return nil, errors.New("an HTML page, not an AI Catalog")
		}

		return nil, fmt.Errorf("not an AI Catalog document: %w", err)
	}

	if strings.TrimSpace(doc.SpecVersion) == "" {
		return nil, errors.New("not an AI Catalog document: no specVersion")
	}

	return doc, nil
}

// linkCandidates returns the catalogs a response points to: first those of its
// Link headers, then those of its HTML link elements.
func linkCandidates(resp *Response) []candidate {
	var candidates []candidate

	for _, target := range targetsWithRel(resp.LinkHeaders, LinkRelation) {
		if u, err := resp.URL.Parse(target); err == nil {
			candidates = append(candidates, candidate{url: u, method: MethodLinkHeader})
		}
	}

	if !resp.isHTML() {
		return candidates
	}

	links := findHTMLLinks(resp.Body, LinkRelation)

	// A base element changes what the other references resolve against.
	base := resp.URL
	if links.base != "" {
		if u, err := resp.URL.Parse(links.base); err == nil {
			base = u
		}
	}

	for _, href := range links.hrefs {
		if u, err := base.Parse(href); err == nil {
			candidates = append(candidates, candidate{url: u, method: MethodHTMLLink})
		}
	}

	return candidates
}
