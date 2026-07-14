// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// CatalogEntry describes a single AI artifact: it identifies the artifact,
// declares its kind via Type, and either references it (URL) or embeds it
// inline (Data). When Version is set, (Identifier, Version) must be unique
// within a catalog; otherwise Identifier alone must be unique.
//
//nolint:revive // "catalog.CatalogEntry" matches the spec and the Rust SDK type name.
type CatalogEntry struct {
	// Identifier is a stable, globally unique identifier, ideally a URN
	// (RFC 8141) or URI.
	Identifier string `json:"identifier"`

	// DisplayName is a human-readable name for the artifact.
	DisplayName string `json:"displayName,omitempty"`

	// Type is the media type of the artifact, e.g.
	// "application/a2a-agent-card+json", "application/mcp-server-card+json",
	// or "application/ai-catalog+json" for a nested catalog.
	Type string `json:"type"`

	// URL is where the artifact document can be retrieved. Exactly one of URL
	// or Data must be set.
	URL string `json:"url,omitempty"`

	// Data is the artifact document embedded inline; its structure follows
	// Type. Exactly one of URL or Data must be set.
	Data json.RawMessage `json:"data,omitempty"`

	// Version is the artifact version. Semantic Versioning is recommended.
	Version string `json:"version,omitempty"`

	// Description of the artifact.
	Description string `json:"description,omitempty"`

	// Tags are free-form keywords for filtering and discovery.
	Tags []string `json:"tags,omitempty"`

	// Publisher is the publishing entity. Canonical location for publisher
	// info, not duplicated in TrustManifest.
	Publisher *Publisher `json:"publisher,omitempty"`

	// TrustManifest holds trust metadata. When present, TrustManifest.Identity
	// must match Identifier.
	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`

	// UpdatedAt is an RFC 3339 timestamp of the last modification to this entry.
	UpdatedAt string `json:"updatedAt,omitempty"`

	// Metadata holds custom or vendor-specific metadata.
	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
}

// IsNestedCatalog reports whether the entry references or embeds another AI
// Catalog (i.e. its Type is "application/ai-catalog+json").
func (e *CatalogEntry) IsNestedCatalog() bool {
	return e.Type == MediaTypeCatalog
}

// Pull fetches the artifact at the entry's URL and returns its raw bytes.
// It returns an error if the entry has no URL (e.g. it embeds inline Data).
func (e *CatalogEntry) Pull(ctx context.Context) ([]byte, error) {
	if e.URL == "" {
		return nil, errors.New("entry has no url to pull from")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch artifact: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return data, nil
}
