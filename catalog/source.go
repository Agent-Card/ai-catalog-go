// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "context"

// Source is a source-agnostic loader for an AI Catalog. The provider package
// ships built-in implementations (JSON, Web, WellKnown, FromCatalog); consumers
// with their own backend can satisfy it directly. Query the loaded document with
// the methods on *AICatalog (GetByID, Search, ...).
type Source interface {
	// Load returns the whole AI Catalog document in memory. Implementations
	// that resolve nested catalogs fold their entries into the returned
	// document. The context governs any I/O and cancellation.
	Load(ctx context.Context) (*AICatalog, error)
}
