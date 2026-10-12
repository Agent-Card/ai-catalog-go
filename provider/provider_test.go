// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Agent-Card/ai-catalog-go/catalog"
	"github.com/Agent-Card/ai-catalog-go/internal/fixture"
)

const financeID = "urn:example:agent:finance-v1"

// serve starts a server that serves body at /catalog.json and returns its URL.
func serve(t *testing.T, body []byte) (string, *http.Client) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/catalog.json" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	return server.URL + "/catalog.json", server.Client()
}

func load(t *testing.T, source catalog.Source) *catalog.AICatalog {
	t.Helper()

	doc, err := source.Load(context.Background())
	if err != nil {
		t.Fatalf("load catalog: %v", err)
	}

	return doc
}

func TestJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(path, fixture.Read(t, "catalog.json"), 0o600); err != nil {
		t.Fatalf("write catalog: %v", err)
	}

	source, err := JSON(path)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	if _, ok := load(t, source).GetByID(financeID); !ok {
		t.Errorf("expected to find %q", financeID)
	}
}

func TestWeb(t *testing.T) {
	url, client := serve(t, fixture.Read(t, "catalog.json"))

	source, err := Web(context.Background(), url, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	if _, ok := load(t, source).GetByID(financeID); !ok {
		t.Errorf("expected to find %q", financeID)
	}

	if _, err := Web(context.Background(), url+".missing", WithHTTPClient(client)); err == nil {
		t.Error("expected an error for a non-200 response")
	}

	badURL, badClient := serve(t, []byte(`not json`))
	if _, err := Web(context.Background(), badURL, WithHTTPClient(badClient)); err == nil {
		t.Error("expected an error for a document that does not parse")
	}
}

// Every Load returns a document the caller owns.
func TestLoad_ReturnsIndependentDocuments(t *testing.T) {
	url, client := serve(t, fixture.Read(t, "catalog.json"))

	source, err := Web(context.Background(), url, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	first := load(t, source)
	first.Entries[0].DisplayName = "Mutated"
	first.Entries = append(first.Entries, catalog.CatalogEntry{Identifier: "urn:mutated"})

	second := load(t, source)

	if second.Entries[0].DisplayName == "Mutated" || len(second.Entries) != len(first.Entries)-1 {
		t.Error("a change to one loaded document leaked into a later Load")
	}
}

// A signature covers the document as served, so the bytes must come back
// unchanged, including members the SDK does not model.
func TestRaw_PreservesServedBytes(t *testing.T) {
	served := fixture.Read(t, "future_member.json")
	url, client := serve(t, served)

	source, err := Web(context.Background(), url, WithHTTPClient(client))
	if err != nil {
		t.Fatalf("Web: %v", err)
	}

	rawSource, ok := source.(catalog.RawSource)
	if !ok {
		t.Fatal("built-in providers must implement catalog.RawSource")
	}

	raw, err := rawSource.Raw(context.Background())
	if err != nil || !bytes.Equal(raw, served) {
		t.Fatalf("Raw = %q, %v, want %q", raw, err, served)
	}

	raw[0] = 'X'

	if again, _ := rawSource.Raw(context.Background()); !bytes.Equal(again, served) {
		t.Error("changing the returned bytes changed the source")
	}
}
