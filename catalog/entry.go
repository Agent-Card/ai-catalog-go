// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
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

	// TrustManifest.Identity must align with Identifier's publisher domain when
	// present.
	TrustManifest *TrustManifest `json:"trustManifest,omitempty"`

	// UpdatedAt is an RFC 3339 timestamp of the last modification.
	UpdatedAt string `json:"updatedAt,omitempty"`

	// Extensions holds custom or vendor-specific members. Keys must be a URL
	// or a reverse-DNS string to keep vendors from colliding.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// IsNestedCatalog reports whether the entry's Type marks it as a nested catalog.
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
