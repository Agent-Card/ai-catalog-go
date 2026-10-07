// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package fixture holds the documents shared across the SDK's tests.
package fixture

import (
	"embed"
	"testing"
)

//go:embed data
var files embed.FS

// Read returns the fixture at name, relative to the data directory.
func Read(tb testing.TB, name string) []byte {
	tb.Helper()

	data, err := files.ReadFile("data/" + name)
	if err != nil {
		tb.Fatalf("read fixture %s: %v", name, err)
	}

	return data
}
