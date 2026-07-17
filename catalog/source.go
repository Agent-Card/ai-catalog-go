// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"errors"
)

// ErrEntryNotFound is returned by Source.GetByID when no entry with the
// requested identifier exists in the (resolved) catalog.
var ErrEntryNotFound = errors.New("catalog entry not found")

// Source is a read-only, source-agnostic handle to an AI Catalog whose lookups
// descend into nested catalogs. The provider package ships built-in
// implementations (JSON, Web, FromCatalog); consumers with their own backend
// can satisfy it directly. Methods take a context.Context for I/O and
// cancellation.
type Source interface {
	// Document returns the top-level AI Catalog document backing this handle.
	Document(ctx context.Context) (*AICatalog, error)

	// GetByID returns the entry whose Identifier equals id. Nested catalogs are
	// searched as well. It returns ErrEntryNotFound (wrapped) when no such
	// entry exists.
	GetByID(ctx context.Context, id string) (*CatalogEntry, error)

	// GetByType returns every entry whose Type (media type) equals mediaType,
	// including entries in nested catalogs. The result is empty when there are
	// no matches.
	GetByType(ctx context.Context, mediaType string) ([]*CatalogEntry, error)

	// Search returns every entry where query appears (case-insensitively) in
	// the Identifier, DisplayName, Description, or any Tags value, including
	// entries in nested catalogs.
	Search(ctx context.Context, query string) ([]*CatalogEntry, error)
}
