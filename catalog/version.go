// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// GetByIDAndVersion returns a pointer to the entry whose Identifier equals id
// and Version equals version, and reports whether such an entry was found. Per
// the spec, the combination of identifier and version is unique within a
// catalog. The pointer references the entry inside the catalog's Entries slice.
func (c *AICatalog) GetByIDAndVersion(id, version string) (*CatalogEntry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id && c.Entries[i].Version == version {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// Versions returns every entry whose Identifier equals id, in document order. A
// catalog may list several versions of the same artifact under one identifier;
// the returned pointers reference entries inside the catalog's Entries slice and
// the result is nil when there are no matches.
func (c *AICatalog) Versions(id string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// GetLatest returns the most recent entry for id and reports whether any entry
// with that identifier exists. Following the spec's multi-version guidance,
// entries whose Version parses as a Semantic Version are preferred and compared
// by semver (ties broken by the more recent UpdatedAt); when no matching entry
// has a parseable version, the entry with the most recent UpdatedAt wins, and
// document order breaks any remaining ties.
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

// semverKey normalizes an artifact version to a valid semver string (with the
// leading "v" that golang.org/x/mod/semver requires) and reports whether it is
// a valid Semantic Version.
func semverKey(version string) (string, bool) {
	if version == "" {
		return "", false
	}

	key := "v" + strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
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
