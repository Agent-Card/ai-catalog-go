// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package validate

import (
	"context"
	"fmt"

	"github.com/agntcy/ai-catalog-go/catalog"
)

// Source validates the AI Catalog document backing c. It is a convenience
// bridge for callers holding a catalog.Source handle (the catalog package
// cannot depend on validate without creating an import cycle).
func Source(ctx context.Context, c catalog.Source) (Result, error) {
	doc, err := c.Load(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("load catalog: %w", err)
	}

	return Validate(doc), nil
}
