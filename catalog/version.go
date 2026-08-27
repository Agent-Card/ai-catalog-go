// Copyright AI-Catalog Contributors (https://github.com/Agent-Card)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// GetByIDAndVersion returns the entry whose Identifier equals id and Version
// equals version, and reports whether one was found. The pair is unique within
// a catalog.
func (c *AICatalog) GetByIDAndVersion(id, version string) (*CatalogEntry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id && c.Entries[i].Version == version {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// Versions returns every entry whose Identifier equals id, in document order,
// or nil when none match.
func (c *AICatalog) Versions(id string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// GetLatest returns the most recent entry for id and whether one exists.
// Entries with a valid semver Version are preferred and compared by semver
// (ties broken by UpdatedAt); otherwise the most recent UpdatedAt wins, with
// document order breaking remaining ties.
func (c *AICatalog) GetLatest(id string) (*CatalogEntry, bool) {
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

	// No entry has a parseable version: fall back to the most recent UpdatedAt,
	// preserving document order for ties.
	best = matches[0]
	for _, e := range matches[1:] {
		if updatedAt(e).After(updatedAt(best)) {
			best = e
		}
	}

	return best, true
}

// semverKey adds the leading "v" that golang.org/x/mod/semver requires and
// reports whether the result is valid semver.
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

// updatedAt parses an entry's UpdatedAt as an RFC 3339 timestamp, returning the
// zero time when it is absent or unparseable.
func updatedAt(e *CatalogEntry) time.Time {
	t, err := time.Parse(time.RFC3339, e.UpdatedAt)
	if err != nil {
		return time.Time{}
	}

	return t
}
