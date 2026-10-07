// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import "context"

// Source loads an AI Catalog. Package provider has built-in implementations;
// any backend can implement it.
type Source interface {
	// Load returns the catalog. Each call returns a document the caller owns,
	// so implementations that cache must return a copy.
	Load(ctx context.Context) (*AICatalog, error)
}

// RawSource is a Source that can return the document exactly as served.
// Signature verification needs those bytes, since re-serializing a parsed
// catalog drops members the SDK does not model.
type RawSource interface {
	Source

	// Raw returns a copy of the original bytes.
	Raw(ctx context.Context) ([]byte, error)
}
