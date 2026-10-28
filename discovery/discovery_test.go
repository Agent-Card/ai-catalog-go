// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

const (
	catalogJSON = `{"specVersion": "1.0", "entries": []}`
	exampleHost = "example.com"
	exampleRoot = "https://example.com/"
)

// fakeFetcher serves canned responses and records the requests.
type fakeFetcher struct {
	responses map[string]*Response
	failures  map[string]string
	requested []string
}

func newFake() *fakeFetcher {
	return &fakeFetcher{responses: map[string]*Response{}, failures: map[string]string{}}
}

func (f *fakeFetcher) serve(rawURL, contentType string, links []string, body string) *fakeFetcher {
	u, _ := url.Parse(rawURL)
	f.responses[rawURL] = &Response{URL: u, StatusCode: http.StatusOK, ContentType: contentType, LinkHeaders: links, Body: []byte(body)}

	return f
}

func (f *fakeFetcher) catalog(rawURL string) *fakeFetcher {
	return f.serve(rawURL, "application/ai-catalog+json", nil, catalogJSON)
}

func (f *fakeFetcher) html(rawURL string, links []string, body string) *fakeFetcher {
	return f.serve(rawURL, "text/html; charset=utf-8", links, body)
}

// redirect serves what is at to under the address from, the way a redirect does.
func (f *fakeFetcher) redirect(from, to string) *fakeFetcher {
	resp := *f.responses[to]
	f.responses[from] = &resp

	return f
}

func (f *fakeFetcher) fail(rawURL, reason string) *fakeFetcher {
	f.failures[rawURL] = reason

	return f
}

func (f *fakeFetcher) Fetch(_ context.Context, u *url.URL) (*Response, error) {
	f.requested = append(f.requested, u.String())

	if reason, ok := f.failures[u.String()]; ok {
		return nil, errors.New(reason)
	}

	if resp, ok := f.responses[u.String()]; ok {
		return resp, nil
	}

	return &Response{URL: u, StatusCode: http.StatusNotFound}, nil
}

func discover(t *testing.T, f *fakeFetcher, input string) *Result {
	t.Helper()

	result, err := Discover(context.Background(), input, WithFetcher(f))
	if err != nil {
		t.Fatalf("Discover(%q): %v", input, err)
	}

	return result
}

func TestDiscoverUsesAURLThatIsACatalog(t *testing.T) {
	f := newFake().catalog("https://example.com/ai.json")

	result := discover(t, f, "https://example.com/ai.json")

	if result.Method != MethodDirect || result.URL != "https://example.com/ai.json" {
		t.Errorf("got %s via %s", result.URL, result.Method)
	}

	if string(result.Raw) != catalogJSON || result.Catalog.SpecVersion != "1.0" {
		t.Errorf("raw %q, spec version %q", result.Raw, result.Catalog.SpecVersion)
	}

	if len(f.requested) != 1 {
		t.Errorf("requested %q", f.requested)
	}
}

func TestDiscoverAcceptsAnyMediaType(t *testing.T) {
	f := newFake().serve("https://example.com/ai.json", "text/plain", nil, catalogJSON)

	if got := discover(t, f, "https://example.com/ai.json").Method; got != MethodDirect {
		t.Errorf("method = %s", got)
	}
}

func TestDiscoverAssumesHTTPSForABareDomain(t *testing.T) {
	f := newFake().catalog(exampleRoot)

	if got := discover(t, f, "  example.com ").URL; got != exampleRoot {
		t.Errorf("url = %s", got)
	}
}

func TestDiscoverFollowsALinkHeader(t *testing.T) {
	f := newFake().
		html(exampleRoot, []string{`</catalog/ai.json>; rel="ai-catalog"`}, "<html></html>").
		catalog("https://example.com/catalog/ai.json")

	result := discover(t, f, exampleHost)

	if result.Method != MethodLinkHeader || result.URL != "https://example.com/catalog/ai.json" {
		t.Errorf("got %s via %s", result.URL, result.Method)
	}
}

func TestDiscoverFollowsAnHTMLLinkElement(t *testing.T) {
	f := newFake().
		html("https://example.com/docs/", nil, `<head><link rel="ai-catalog" href="../ai.json" type="application/ai-catalog+json"></head>`).
		catalog("https://example.com/ai.json")

	result := discover(t, f, "https://example.com/docs/")

	if result.Method != MethodHTMLLink || result.URL != "https://example.com/ai.json" {
		t.Errorf("got %s via %s", result.URL, result.Method)
	}
}

func TestDiscoverFallsBackToTheWellKnownURI(t *testing.T) {
	f := newFake().
		html(exampleRoot, nil, "<html><head></head></html>").
		catalog("https://example.com/.well-known/ai-catalog.json")

	if got := discover(t, f, exampleHost).Method; got != MethodWellKnown {
		t.Errorf("method = %s", got)
	}
}

func TestDiscoverTriesTheWellKnownURIWhenThePageCannotBeFetched(t *testing.T) {
	f := newFake().
		fail(exampleRoot, "connection reset").
		catalog("https://example.com/.well-known/ai-catalog.json")

	if got := discover(t, f, exampleHost).Method; got != MethodWellKnown {
		t.Errorf("method = %s", got)
	}
}

func TestDiscoverTriesTheWellKnownURIOfTheHostAfterARedirectFirst(t *testing.T) {
	f := newFake().
		html("https://www.example.com/", nil, "<html></html>").
		redirect(exampleRoot, "https://www.example.com/").
		catalog("https://www.example.com/.well-known/ai-catalog.json")

	result := discover(t, f, exampleHost)

	if result.URL != "https://www.example.com/.well-known/ai-catalog.json" {
		t.Errorf("url = %s", result.URL)
	}

	if last := f.requested[len(f.requested)-1]; last != result.URL {
		t.Errorf("requests = %q", f.requested)
	}
}

func TestDiscoverPrefersALinkHeaderToAnHTMLLinkAndTheWellKnownURI(t *testing.T) {
	f := newFake().
		html(exampleRoot, []string{"</from-header.json>; rel=ai-catalog"}, `<link rel="ai-catalog" href="/from-html.json">`).
		catalog("https://example.com/from-header.json").
		catalog("https://example.com/from-html.json").
		catalog("https://example.com/.well-known/ai-catalog.json")

	if got := discover(t, f, exampleHost).Method; got != MethodLinkHeader {
		t.Errorf("method = %s", got)
	}

	if len(f.requested) != 2 {
		t.Errorf("requested %q", f.requested)
	}
}

func TestDiscoverKeepsLookingAfterABrokenLink(t *testing.T) {
	f := newFake().
		html(exampleRoot, []string{"</gone.json>; rel=ai-catalog"}, `<link rel="ai-catalog" href="/not-a-catalog.json">`).
		serve("https://example.com/not-a-catalog.json", "application/json", nil, `{"hello": 1}`).
		catalog("https://example.com/.well-known/ai-catalog.json")

	if got := discover(t, f, exampleHost).Method; got != MethodWellKnown {
		t.Errorf("method = %s", got)
	}
}

func TestDiscoverRequestsAURLOnce(t *testing.T) {
	f := newFake().html(
		exampleRoot,
		[]string{"</.well-known/ai-catalog.json>; rel=ai-catalog"},
		`<link rel="ai-catalog" href="/.well-known/ai-catalog.json#frag">`,
	)

	if _, err := Discover(context.Background(), exampleHost, WithFetcher(f)); err == nil {
		t.Fatal("expected an error")
	}

	want := []string{exampleRoot, "https://example.com/.well-known/ai-catalog.json"}
	if strings.Join(f.requested, " ") != strings.Join(want, " ") {
		t.Errorf("requested %q, want %q", f.requested, want)
	}
}

func TestDiscoverDoesNotFollowLinksToOtherSchemes(t *testing.T) {
	f := newFake().html(exampleRoot, []string{"<http://example.com/ai.json>; rel=ai-catalog", "<file:///etc/passwd>; rel=ai-catalog"}, "")

	_, err := Discover(context.Background(), exampleHost, WithFetcher(f))

	for _, requested := range f.requested {
		if !strings.HasPrefix(requested, "https://") {
			t.Errorf("requested %s", requested)
		}
	}

	if err == nil || !strings.Contains(err.Error(), "not an https URL") {
		t.Errorf("err = %v", err)
	}
}

func TestDiscoverRejectsDocumentsWithoutASpecVersion(t *testing.T) {
	for _, body := range []string{"{}", `{"entries": []}`, `{"specVersion": " "}`, "[]", "null"} {
		f := newFake().serve("https://example.com/ai.json", "application/json", nil, body)

		if _, err := Discover(context.Background(), "https://example.com/ai.json", WithFetcher(f)); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v", body, err)
		}
	}
}

func TestDiscoverNamesEverythingThatWasTried(t *testing.T) {
	f := newFake().html(exampleRoot, nil, "<html></html>")

	_, err := Discover(context.Background(), exampleHost, WithFetcher(f))

	var notFound *NotFoundError
	if !errors.As(err, &notFound) || !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}

	want := []Attempt{
		{URL: exampleRoot, Method: MethodDirect, Reason: "an HTML page, not an AI Catalog"},
		{URL: "https://example.com/.well-known/ai-catalog.json", Method: MethodWellKnown, Reason: "HTTP 404"},
	}

	if len(notFound.Attempts) != len(want) {
		t.Fatalf("attempts = %+v", notFound.Attempts)
	}

	for i := range want {
		if notFound.Attempts[i] != want[i] {
			t.Errorf("attempt %d = %+v, want %+v", i, notFound.Attempts[i], want[i])
		}
	}

	if !strings.Contains(err.Error(), "/.well-known/ai-catalog.json (well-known): HTTP 404") {
		t.Errorf("message = %s", err)
	}
}

func TestDiscoverRejectsInputThatIsNotAnHTTPSURL(t *testing.T) {
	f := newFake()

	for _, input := range []string{"", "   ", "http://example.com", "ftp://example.com", "file:///tmp/a.json", "https://", "exa mple.com"} {
		if _, err := Discover(context.Background(), input, WithFetcher(f)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: err = %v", input, err)
		}
	}

	if len(f.requested) != 0 {
		t.Errorf("requested %q", f.requested)
	}
}

func TestDiscoverStopsWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := newFake()
	if _, err := Discover(ctx, exampleHost, WithFetcher(f)); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

// serveTLS starts an https server and returns its host and a client that trusts it.
func serveTLS(t *testing.T, handler http.HandlerFunc) (string, *http.Client) {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	u, _ := url.Parse(server.URL)

	return u.Host, server.Client()
}

func TestDiscoverOverHTTP(t *testing.T) {
	host, client := serveTLS(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Add("Link", `</other>; rel=next`)
			w.Header().Add("Link", `</catalog/ai.json>; rel="ai-catalog"`)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html></html>"))
		case "/catalog/ai.json":
			w.Header().Set("Content-Type", catalog.MediaTypeCatalog)
			_, _ = w.Write([]byte(catalogJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	result, err := Discover(context.Background(), host, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if result.Method != MethodLinkHeader || result.URL != "https://"+host+"/catalog/ai.json" {
		t.Errorf("got %s via %s", result.URL, result.Method)
	}
}

func TestDefaultClientRefusesARedirectToHTTP(t *testing.T) {
	check := defaultHTTPClient().CheckRedirect

	if err := check(&http.Request{URL: &url.URL{Scheme: "http", Host: exampleHost}}, nil); err == nil {
		t.Error("expected an error for http")
	}

	if err := check(&http.Request{URL: &url.URL{Scheme: "https", Host: exampleHost}}, make([]*http.Request, maxRedirects)); err == nil {
		t.Error("expected an error for too many redirects")
	}

	if err := check(&http.Request{URL: &url.URL{Scheme: "https", Host: exampleHost}}, nil); err != nil {
		t.Errorf("https redirect: %v", err)
	}
}

func TestHTTPFetcherRefusesOversizedBodies(t *testing.T) {
	host, client := serveTLS(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxBodyBytes+1))
	})

	_, err := Discover(context.Background(), "https://"+host+"/ai.json", WithHTTPClient(client))

	var notFound *NotFoundError
	if !errors.As(err, &notFound) || !strings.Contains(notFound.Attempts[0].Reason, "larger than") {
		t.Errorf("err = %v", err)
	}
}
