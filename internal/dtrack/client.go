// Package dtrack is a small read-only client for the Dependency-Track REST
// API (v1). It only knows the endpoints the MCP tools need.
package dtrack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// PageSize is the page size requested from Dependency-Track.
	PageSize = 100

	// maxBodyBytes bounds how much of one response is read.
	maxBodyBytes = 32 << 20
)

// Credential is what Dependency-Track authenticates a request with. Exactly
// one field should be set. The server has no permission model of its own:
// whatever this credential may see in Dependency-Track is what a caller sees.
type Credential struct {
	// APIKey is sent as the X-Api-Key header.
	APIKey string
	// Bearer is sent as "Authorization: Bearer <token>".
	Bearer string
}

// IsZero reports whether no credential is set.
func (c Credential) IsZero() bool { return c.APIKey == "" && c.Bearer == "" }

// Options configures a Client.
type Options struct {
	// BaseURL is the Dependency-Track API server, for example
	// https://dtrack.example.com. A trailing /api is accepted.
	BaseURL string
	// Timeout bounds each request to Dependency-Track. Default 30s.
	Timeout time.Duration
	// MaxConcurrency bounds requests in flight to Dependency-Track across
	// all callers. Default 4.
	MaxConcurrency int
	// UserAgent is sent with every request.
	UserAgent string
	// HTTPClient overrides the HTTP client. Optional.
	HTTPClient *http.Client
}

// Client talks to one Dependency-Track API server.
type Client struct {
	base      *url.URL
	hc        *http.Client
	timeout   time.Duration
	slots     chan struct{}
	userAgent string
}

// New returns a Client for the API server at opts.BaseURL.
func New(opts Options) (*Client, error) {
	raw := strings.TrimSuffix(strings.TrimRight(opts.BaseURL, "/"), "/api")
	if raw == "" {
		return nil, errors.New("Dependency-Track URL is empty")
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse Dependency-Track URL: %w", err)
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("Dependency-Track URL %q must be an http or https URL", opts.BaseURL)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 4
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{}
	}
	return &Client{
		base:      base,
		hc:        opts.HTTPClient,
		timeout:   opts.Timeout,
		slots:     make(chan struct{}, opts.MaxConcurrency),
		userAgent: opts.UserAgent,
	}, nil
}

// APIError is a non-2xx response from Dependency-Track.
type APIError struct {
	Status int
	Path   string
	Body   string
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "Dependency-Track rejected the credential (401): the API key or token is missing, wrong or expired"
	case http.StatusForbidden:
		return fmt.Sprintf("Dependency-Track denied access to %s (403): the credential lacks the permission or the project access this needs", e.Path)
	case http.StatusNotFound:
		return fmt.Sprintf("Dependency-Track has nothing at %s (404)", e.Path)
	}
	msg := fmt.Sprintf("Dependency-Track answered %d for %s", e.Status, e.Path)
	if e.Body != "" {
		msg += ": " + e.Body
	}
	return msg
}

// IsNotFound reports whether err is a 404 from Dependency-Track.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// get performs one GET and decodes the JSON body into out. It returns the
// X-Total-Count header, or -1 when the server sent none.
func (c *Client) get(ctx context.Context, cred Credential, path string, query url.Values, out any) (int, error) {
	if cred.IsZero() {
		return 0, errors.New("no Dependency-Track credential: set DTRACK_API_KEY, or send an X-Api-Key or Authorization header with the request")
	}

	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	u := c.base.JoinPath("api", path)
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if cred.APIKey != "" {
		req.Header.Set("X-Api-Key", cred.APIKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+cred.Bearer)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			// url.Error prints the full URL; keep the message to the cause.
			err = urlErr.Err
		}
		return 0, fmt.Errorf("request to Dependency-Track failed for /api/%s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return 0, &APIError{Status: resp.StatusCode, Path: "/api/" + path, Body: strings.TrimSpace(string(snippet))}
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out); err != nil {
		return 0, fmt.Errorf("decode Dependency-Track response for /api/%s: %w", path, err)
	}

	total := -1
	if h := resp.Header.Get("X-Total-Count"); h != "" {
		if n, err := strconv.Atoi(h); err == nil {
			total = n
		}
	}
	return total, nil
}

// Page is one bounded read of a list endpoint.
type Page[T any] struct {
	Items []T
	// Total is the number of items Dependency-Track holds for the query, or
	// -1 when it did not say.
	Total int
	// Complete is true when Items holds everything Dependency-Track has for
	// the query. False means the page limit stopped the read early.
	Complete bool
	// Requests is how many requests the read made.
	Requests int
}

// list reads up to maxPages pages of a list endpoint. It stops as soon as the
// server has no more, so a short list costs one request.
func list[T any](ctx context.Context, c *Client, cred Credential, path string, query url.Values, pageSize, maxPages int) (Page[T], error) {
	page := Page[T]{Total: -1, Items: []T{}}
	if query == nil {
		query = url.Values{}
	}
	query.Set("pageSize", strconv.Itoa(pageSize))

	for n := 1; n <= maxPages; n++ {
		query.Set("pageNumber", strconv.Itoa(n))
		var items []T
		total, err := c.get(ctx, cred, path, query, &items)
		if err != nil {
			return page, err
		}
		page.Requests++
		page.Items = append(page.Items, items...)
		if total >= 0 {
			page.Total = total
		}

		// Done when the server returned a short page, more than it was
		// asked for (older versions ignore paging on some endpoints and
		// return everything), or everything it counted.
		if len(items) != pageSize || (total >= 0 && len(page.Items) >= total) {
			page.Complete = true
			break
		}
	}
	// A complete read is its own count when the server sent none.
	if page.Complete && page.Total < len(page.Items) {
		page.Total = len(page.Items)
	}
	return page, nil
}
