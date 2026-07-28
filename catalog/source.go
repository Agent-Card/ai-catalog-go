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
	// Each call returns a fresh document that the caller owns and may read or
	// mutate freely without affecting the Source or other callers; the
	// built-in providers re-parse on every call. Implementations backed by a
	// shared, cached value SHOULD return an independent copy.
	Load(ctx context.Context) (*AICatalog, error)
}
