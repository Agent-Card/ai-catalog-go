// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// GetByIDAndVersion returns the entry with the given identifier and version.
func (c AICatalog) GetByIDAndVersion(id, version string) (*CatalogEntry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id && c.Entries[i].Version == version {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// Versions returns the entries with the given identifier, in document order.
func (c AICatalog) Versions(id string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// GetLatest returns the latest entry for id. A valid semver version wins,
// compared by semver and then UpdatedAt; without one the latest UpdatedAt wins.
// Document order breaks remaining ties.
func (c AICatalog) GetLatest(id string) (*CatalogEntry, bool) {
	matches := c.Versions(id)
	if len(matches) == 0 {
		return nil, false
	}

	var (
		best   *CatalogEntry
		bestSV string
	)

	for _, e := range matches {
		key, ok := semverKey(e.Version)
		if !ok {
			continue
		}

		switch {
		case best == nil:
			best, bestSV = e, key
		case semver.Compare(key, bestSV) > 0:
			best, bestSV = e, key
		case semver.Compare(key, bestSV) == 0 && updatedAt(e).After(updatedAt(best)):
			best, bestSV = e, key
		}
	}

	if best != nil {
		return best, true
	}

	// No parseable version: use the latest UpdatedAt.
	best = matches[0]
	for _, e := range matches[1:] {
		if updatedAt(e).After(updatedAt(best)) {
			best = e
		}
	}

	return best, true
}

// semverKey returns version as x/mod/semver expects it ("v" prefix) and whether
// it is valid.
func semverKey(version string) (string, bool) {
	if version == "" {
		return "", false
	}

	key := "v" + strings.TrimLeft(version, "vV")
	if !semver.IsValid(key) {
		return "", false
	}

	return key, true
}

// updatedAt returns the entry's UpdatedAt, or the zero time when absent or invalid.
func updatedAt(e *CatalogEntry) time.Time {
	t, err := time.Parse(time.RFC3339, e.UpdatedAt)
	if err != nil {
		return time.Time{}
	}

	return t
}
