// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package catalog provides types and helpers for the AI Catalog specification
// (https://agent-card.github.io/ai-catalog/): parsing, serializing, searching,
// and navigating AI Catalog documents.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
)

// MediaTypeCatalog is the media type identifying a (possibly nested) AI Catalog
// document. An entry whose Type equals this value embeds or references another
// AI Catalog.
const MediaTypeCatalog = "application/ai-catalog+json"

// AICatalog is the top-level container for discovering heterogeneous AI
// artifacts (MCP servers, A2A agents, skills, nested catalogs, etc.).
// It is serialized as media type "application/ai-catalog+json".
type AICatalog struct {
	// SpecVersion is the AI Catalog spec version this document conforms to,
	// as "Major.Minor".
	SpecVersion string `json:"specVersion"`

	// Host is the operator of this catalog. Required at the
	// Discoverable/Trusted conformance levels.
	Host *HostInfo `json:"host,omitempty"`

	// Entries are the catalog entries. May be empty.
	Entries []CatalogEntry `json:"entries"`

	// Metadata holds custom or vendor-specific metadata.
	Metadata map[string]json.RawMessage `json:"metadata,omitempty"`
}

// GetByID returns a pointer to the first entry whose Identifier exactly matches
// id, and reports whether such an entry was found. The pointer references the
// entry inside the catalog's Entries slice.
func (c *AICatalog) GetByID(id string) (*CatalogEntry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// Search returns all entries where query appears (case-insensitively) in the
// Identifier, DisplayName, Description, or any Tags value.
func (c *AICatalog) Search(query string) []*CatalogEntry {
	lowered := strings.ToLower(query)

	var results []*CatalogEntry

	for i := range c.Entries {
		entry := &c.Entries[i]
		if entryMatchesSubstring(entry, lowered) {
			results = append(results, entry)
		}
	}

	return results
}

// SearchByRegex returns all entries where pattern matches the Identifier,
// DisplayName, Description, or any Tags value. The pattern is used verbatim
// (it is not made case-insensitive). It returns an error if pattern is not a
// valid regular expression.
func (c *AICatalog) SearchByRegex(pattern string) ([]*CatalogEntry, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}

	var results []*CatalogEntry

	for i := range c.Entries {
		entry := &c.Entries[i]
		if entryMatchesRegex(entry, re) {
			results = append(results, entry)
		}
	}

	return results, nil
}

// ToJSON serializes the catalog to compact JSON.
func (c *AICatalog) ToJSON() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// ToJSONIndent serializes the catalog to indented (pretty) JSON.
func (c *AICatalog) ToJSONIndent() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// WriteJSON writes the catalog as indented (pretty) JSON to w.
func (c *AICatalog) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode catalog: %w", err)
	}

	return nil
}

// Parse parses an AI Catalog document from raw JSON bytes.
func Parse(data []byte) (*AICatalog, error) {
	var c AICatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog JSON: %w", err)
	}

	return &c, nil
}

// ParseString parses an AI Catalog document from a JSON string.
func ParseString(s string) (*AICatalog, error) {
	return Parse([]byte(s))
}

// ParseReader parses an AI Catalog document from an io.Reader.
func ParseReader(r io.Reader) (*AICatalog, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	return Parse(data)
}

// ParseFile loads and parses an AI Catalog document from a local JSON file.
func ParseFile(path string) (*AICatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}

	return Parse(data)
}

// FromURL fetches and parses an AI Catalog document from a remote URL.
func FromURL(ctx context.Context, url string) (*AICatalog, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch catalog: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return ParseReader(resp.Body)
}

// entryMatchesSubstring reports whether the lowercased query is a substring of
// any searchable field of entry.
func entryMatchesSubstring(entry *CatalogEntry, loweredQuery string) bool {
	if strings.Contains(strings.ToLower(entry.Identifier), loweredQuery) ||
		strings.Contains(strings.ToLower(entry.DisplayName), loweredQuery) ||
		strings.Contains(strings.ToLower(entry.Description), loweredQuery) {
		return true
	}

	for _, tag := range entry.Tags {
		if strings.Contains(strings.ToLower(tag), loweredQuery) {
			return true
		}
	}

	return false
}

// entryMatchesRegex reports whether re matches any searchable field of entry.
func entryMatchesRegex(entry *CatalogEntry, re *regexp.Regexp) bool {
	if re.MatchString(entry.Identifier) ||
		re.MatchString(entry.DisplayName) ||
		re.MatchString(entry.Description) {
		return true
	}

	return slices.ContainsFunc(entry.Tags, re.MatchString)
}
