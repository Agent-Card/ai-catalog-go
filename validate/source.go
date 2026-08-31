// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"fmt"

	"github.com/Agent-Card/ai-catalog-go/catalog"
)

// Source loads the AI Catalog document behind c and validates it, for callers
// holding a catalog.Source rather than an already-parsed document.
func Source(ctx context.Context, c catalog.Source) (Result, error) {
	doc, err := c.Load(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("load catalog: %w", err)
	}

	return Validate(doc), nil
}
