// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

// Package catalog is the AI Catalog document model (https://ai-catalog.io/spec/):
// parsing, serializing and querying.
package catalog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// WellKnownPath is the well-known URI path of an AI Catalog.
const WellKnownPath = "/.well-known/ai-catalog.json"

// AICatalog is the top-level AI Catalog document.
type AICatalog struct {
	// SpecVersion is the spec version, as "Major.Minor".
	SpecVersion string `json:"specVersion"`

	// Host is the catalog operator; Discoverable and above require it.
	Host *HostInfo `json:"host,omitempty"`

	// Entries may be empty.
	Entries []CatalogEntry `json:"entries"`

	// Signature is a detached JWS over the JCS-canonicalized document without
	// this member.
	Signature string `json:"signature,omitempty"`

	// Extensions holds vendor-specific members; keys must be a URL or a
	// reverse-DNS string.
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

// MarshalJSON writes empty Entries as [] rather than null.
func (c AICatalog) MarshalJSON() ([]byte, error) {
	type alias AICatalog

	proxy := alias(c)
	if proxy.Entries == nil {
		proxy.Entries = []CatalogEntry{}
	}

	data, err := json.Marshal(proxy)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// GetByID returns the first entry with the given identifier.
func (c AICatalog) GetByID(id string) (*CatalogEntry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// GetByType returns the entries of the given media type.
func (c AICatalog) GetByType(mediaType string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if c.Entries[i].Type == mediaType {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// GetByTag returns the entries carrying the exact tag.
func (c AICatalog) GetByTag(tag string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if slices.Contains(c.Entries[i].Tags, tag) {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// GetByPublisher returns the entries published by the given identifier.
func (c AICatalog) GetByPublisher(id string) []*CatalogEntry {
	var results []*CatalogEntry

	for i := range c.Entries {
		if p := c.Entries[i].Publisher; p != nil && p.Identifier == id {
			results = append(results, &c.Entries[i])
		}
	}

	return results
}

// Search returns the entries whose identifier, display name, description or
// tags contain query, ignoring case.
func (c AICatalog) Search(query string) []*CatalogEntry {
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

// SearchByRegex returns the entries whose identifier, display name, description
// or tags match pattern.
func (c AICatalog) SearchByRegex(pattern string) ([]*CatalogEntry, error) {
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
func (c AICatalog) ToJSON() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// ToJSONIndent serializes the catalog to indented JSON.
func (c AICatalog) ToJSONIndent() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// WriteJSON writes the catalog to w as indented JSON.
func (c AICatalog) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode catalog: %w", err)
	}

	return nil
}

// Parse parses a catalog from JSON.
func Parse(data []byte) (*AICatalog, error) {
	var c AICatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog JSON: %w", err)
	}

	return &c, nil
}

// ParseString parses a catalog from a JSON string.
func ParseString(s string) (*AICatalog, error) {
	return Parse([]byte(s))
}

// ParseReader parses a catalog from r.
func ParseReader(r io.Reader) (*AICatalog, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	return Parse(data)
}

// ParseFile parses a catalog from a JSON file.
func ParseFile(path string) (*AICatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}

	return Parse(data)
}

// entryMatchesSubstring reports whether the lowercased query occurs in a searchable field.
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

// entryMatchesRegex reports whether re matches a searchable field.
func entryMatchesRegex(entry *CatalogEntry, re *regexp.Regexp) bool {
	if re.MatchString(entry.Identifier) ||
		re.MatchString(entry.DisplayName) ||
		re.MatchString(entry.Description) {
		return true
	}

	return slices.ContainsFunc(entry.Tags, re.MatchString)
}
