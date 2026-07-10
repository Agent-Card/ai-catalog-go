// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type AICatalog struct {
	SpecVersion string  `json:"specVersion"`
	Host        Host    `json:"host"`
	Entries     []Entry `json:"entries"`
}

type Host struct {
	DisplayName      string `json:"displayName,omitempty"`
	Identifier       string `json:"identifier"`
	DocumentationURL string `json:"documentationURL,omitempty"`
}

// Search returns all entries whose searchable fields match the query.
// The query is first compiled as a regular expression; if it is not a valid
// regex, a case-insensitive substring match is used instead.
func (c *AICatalog) Search(query string) []Entry {
	re, useRegex := tryCompileRegex(query)

	var results []Entry

	for _, entry := range c.Entries {
		if matchesEntry(entry, query, re, useRegex) {
			results = append(results, entry)
		}
	}

	return results
}

// GetById returns the entry with the given identifier, or (nil, false) if not found.
func (c *AICatalog) GetById(id string) (*Entry, bool) {
	for i := range c.Entries {
		if c.Entries[i].Identifier == id {
			return &c.Entries[i], true
		}
	}

	return nil, false
}

// Validate checks the catalog against the AI Catalog specification rules.
func (c *AICatalog) Validate() error {
	if c.SpecVersion == "" {
		return errors.New("specVersion must not be empty")
	}

	if c.Host.Identifier == "" {
		return errors.New("host.identifier must not be empty")
	}

	seen := make(map[string]bool, len(c.Entries))

	for _, entry := range c.Entries {
		if entry.MediaType == "" {
			return fmt.Errorf("entry %q: mediaType must not be empty", entry.Identifier)
		}

		if seen[entry.Identifier] {
			return fmt.Errorf("duplicate entry identifier: %q", entry.Identifier)
		}

		seen[entry.Identifier] = true
	}

	return nil
}

// MarshalToJSON serializes the catalog to canonical JSON.
func (c *AICatalog) MarshalToJSON() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal catalog: %w", err)
	}

	return data, nil
}

// FromJSON parses a catalog from raw JSON bytes.
func FromJSON(data []byte) (*AICatalog, error) {
	var c AICatalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse catalog JSON: %w", err)
	}

	return &c, nil
}

// FromFile loads a catalog from a local JSON file.
func FromFile(path string) (*AICatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog file: %w", err)
	}

	return FromJSON(data)
}

// FromURL fetches and parses a catalog from a remote URL.
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

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return FromJSON(data)
}

// tryCompileRegex attempts to compile query as a case-insensitive regular expression.
// Returns (nil, false) when the query is not valid regex.
func tryCompileRegex(query string) (*regexp.Regexp, bool) {
	re, err := regexp.Compile("(?i)" + query)
	if err != nil {
		return nil, false
	}

	return re, true
}

// fixedSearchFields is the number of non-tag fields inspected by matchesEntry.
const fixedSearchFields = 3

// matchesEntry reports whether any searchable field of entry matches the query.
func matchesEntry(entry Entry, query string, re *regexp.Regexp, useRegex bool) bool {
	fields := make([]string, 0, fixedSearchFields+len(entry.Tags))
	fields = append(fields, entry.Identifier, entry.DisplayName, entry.Description)
	fields = append(fields, entry.Tags...)

	lowerQuery := strings.ToLower(query)

	for _, field := range fields {
		if useRegex {
			if re.MatchString(field) {
				return true
			}
		} else {
			if strings.Contains(strings.ToLower(field), lowerQuery) {
				return true
			}
		}
	}

	return false
}
