// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "context"

// Source is a source-agnostic loader for an AI Catalog. The provider package
// ships built-in implementations (JSON, Web); consumers
// with their own backend can satisfy it directly. Query the loaded document with
// the methods on *AICatalog (GetByID, Search, ...).
type Source interface {
	// Load returns the whole AI Catalog document in memory. The context
	// governs any I/O and cancellation.
	//
	// The returned document is owned by the Source and must be treated as
	// read-only: implementations may return a shared, cached value, so
	// mutating it can corrupt state observed by other callers. Callers that
	// need to modify the document should copy it first.
	Load(ctx context.Context) (*AICatalog, error)
}
