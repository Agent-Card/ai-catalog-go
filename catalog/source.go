// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "context"

// Source is a source-agnostic loader for an AI Catalog. The provider package
// ships built-in implementations (JSON, Web); consumers with their own backend
// can satisfy it directly. Query the loaded document with the methods on
// *AICatalog (GetByID, Search, ...).
type Source interface {
	// Load returns the whole AI Catalog document in memory. The context
	// governs any I/O and cancellation.
	//
	// Each call returns a fresh document that the caller owns and may read or
	// mutate freely without affecting the Source or other callers. The
	// built-in providers re-parse on every call; implementations backed by a
	// shared, cached value SHOULD return an independent copy.
	Load(ctx context.Context) (*AICatalog, error)
}

// RawSource is an optional capability for a Source that can also return the
// document exactly as it was served. Signature verification requires those
// bytes, because re-serializing a parsed *AICatalog drops any member this SDK
// does not model. Callers detect the capability with a type assertion:
//
//	if raw, ok := source.(catalog.RawSource); ok {
//		data, err := raw.Raw(ctx)
//	}
type RawSource interface {
	Source

	// Raw returns the document's original bytes. Each call returns a slice the
	// caller owns and may modify freely.
	Raw(ctx context.Context) ([]byte, error)
}
