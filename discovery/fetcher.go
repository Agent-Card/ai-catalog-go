// Copyright AI-Catalog Contributors (https://github.com/Agent-Card/ai-catalog-go)
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"
)

const (
	bytesPerMiB = 1 << 20

	maxBodyMiB = 10

	// maxBodyBytes caps a response body.
	maxBodyBytes = maxBodyMiB * bytesPerMiB

	// defaultTimeout bounds a request.
	defaultTimeout = 30 * time.Second

	maxRedirects = 10
)

// Response is an HTTP response, reduced to what discovery looks at.
type Response struct {
	// URL is where the body was served from, after redirects.
	URL        *url.URL
	StatusCode int
	// ContentType is the value of the Content-Type header.
	ContentType string
	// LinkHeaders holds the value of every Link header field.
	LinkHeaders []string
	Body        []byte
}

func (r *Response) success() bool {
	return r.StatusCode >= http.StatusOK && r.StatusCode < http.StatusMultipleChoices
}

func (r *Response) isHTML() bool {
	mediaType, _, err := mime.ParseMediaType(r.ContentType)
	if err != nil {
		return false
	}

	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

// Fetcher performs the GET requests of discovery. Implement it to use another
// HTTP stack, to add authentication or caching, or to restrict where requests
// may go.
//
// A response with an error status is a Response, not an error; the error is for
// a request that got no response at all.
type Fetcher interface {
	Fetch(ctx context.Context, u *url.URL) (*Response, error)
}

// httpFetcher is the default Fetcher, backed by an *http.Client.
type httpFetcher struct {
	client *http.Client
}

// defaultHTTPClient follows redirects only to https URLs and sets a timeout,
// unlike http.DefaultClient.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: defaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != schemeHTTPS {
				return errors.New("refusing to follow a redirect to a non-https URL")
			}

			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}

			return nil
		},
	}
}

func (f httpFetcher) Fetch(ctx context.Context, u *url.URL) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		// The error names the URL already.
		if urlErr, ok := errors.AsType[*url.Error](err); ok {
			err = urlErr.Err
		}

		return nil, err //nolint:wrapcheck // The cause is all the caller needs.
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("the response is larger than %d MiB", maxBodyMiB)
	}

	return &Response{
		URL:         resp.Request.URL,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		LinkHeaders: resp.Header.Values("Link"),
		Body:        body,
	}, nil
}

func describeStatus(status int) string {
	return fmt.Sprintf("HTTP %d", status)
}
