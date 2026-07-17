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
	"strings"
)

// CatalogEntry describes a single AI artifact: it identifies the artifact,
// declares its kind via Type, and either references it (URL) or embeds it
// inline (Data).
//
//nolint:revive // "catalog.CatalogEntry" matches the spec type name.
type CatalogEntry struct {
	// Identifier is a stable, globally unique identifier, ideally a URN or URI.
	Identifier string `json:"identifier"`

	DisplayName string `json:"displayName,omitempty"`

	// Type is the media type of the artifact;
	// "application/ai-catalog+json" denotes a nested catalog.
	Type string `json:"type"`

	// URL and Data are mutually exclusive: exactly one must be set.
	URL  string          `json:"url,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`

	Version     string   `json:"version,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	Publisher *Publisher `json:"publisher,omitempty"`

	// TrustManifest.Identity must match Identifier when present.
	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`

	// UpdatedAt is an RFC 3339 timestamp of the last modification.
	UpdatedAt string `json:"updatedAt,omitempty"`

	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
}

// IsNestedCatalog reports whether the entry references or embeds another AI
// Catalog (i.e. its Type is "application/ai-catalog+json").
func (e *CatalogEntry) IsNestedCatalog() bool {
	return e.Type == MediaTypeCatalog
}

// ResolveDisplayName returns the entry's DisplayName when set, otherwise the
// trailing segment of Identifier (the portion after its final ':' or '/').
func (e *CatalogEntry) ResolveDisplayName() string {
	if e.DisplayName != "" {
		return e.DisplayName
	}

	if i := strings.LastIndexAny(e.Identifier, ":/"); i >= 0 {
		return e.Identifier[i+1:]
	}

	return e.Identifier
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
