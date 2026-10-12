// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"strings"
)

// CatalogEntry describes one AI artifact, referenced by URL or embedded as Data.
//
//nolint:revive // "catalog.CatalogEntry" matches the spec type name.
type CatalogEntry struct {
	// Identifier is a stable, unique identifier, ideally a URN or URI.
	Identifier string `json:"identifier"`

	DisplayName string `json:"displayName,omitempty"`

	// Type is the artifact's media type; MediaTypeCatalog marks a nested catalog.
	Type string `json:"type"`

	// Exactly one of URL and Data must be set.
	URL  string          `json:"url,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`

	Version     string   `json:"version,omitempty"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	Publisher *Publisher `json:"publisher,omitempty"`

	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`

	// UpdatedAt is an RFC 3339 timestamp of the last modification.
	UpdatedAt string `json:"updatedAt,omitempty"`

	// Extensions holds vendor-specific members; keys must be a URL or a
	// reverse-DNS string.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// IsNestedCatalog reports whether the entry is a nested catalog.
func (e *CatalogEntry) IsNestedCatalog() bool {
	return e.Type == MediaTypeCatalog
}

// ResolveDisplayName returns DisplayName, or else the last segment of
// Identifier (after the final ':' or '/').
func (e *CatalogEntry) ResolveDisplayName() string {
	if e.DisplayName != "" {
		return e.DisplayName
	}

	if i := strings.LastIndexAny(e.Identifier, ":/"); i >= 0 {
		return e.Identifier[i+1:]
	}

	return e.Identifier
}
