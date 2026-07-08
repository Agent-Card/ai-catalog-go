// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Entry represents a single catalog entry.
type Entry struct {
	Identifier  string     `json:"identifier"`
	DisplayName string     `json:"displayName,omitempty"`
	MediaType   string     `json:"mediaType"`
	Description string     `json:"description,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
	URL         string     `json:"url"`
	UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
}

// GetIdentifier returns the entry identifier.
func (e *Entry) GetIdentifier() string { return e.Identifier }

// GetDisplayName returns the entry display name.
func (e *Entry) GetDisplayName() string { return e.DisplayName }

// GetMediaType returns the entry media type.
func (e *Entry) GetMediaType() string { return e.MediaType }

// GetDescription returns the entry description.
func (e *Entry) GetDescription() string { return e.Description }

// GetTags returns the entry tags.
func (e *Entry) GetTags() []string { return e.Tags }

// GetURL returns the entry URL.
func (e *Entry) GetURL() string { return e.URL }

// GetUpdatedAt returns the entry update timestamp.
func (e *Entry) GetUpdatedAt() *time.Time { return e.UpdatedAt }

// Pull fetches the artifact at the entry's URL and returns its raw bytes.
func (e *Entry) Pull(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch artifact: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	return data, nil
}
