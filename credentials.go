package blob

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RetryConfig is how the SDK retries a failed request: a 5xx, a 429 or a dropped connection on a
// request that is safe to send twice, a signing call, and a credential the service asked to wait for.
// The zero value keeps the defaults.
type RetryConfig struct {
	// Disabled sends every request once.
	Disabled bool
	// Retries after the first attempt. Zero keeps the defaults: 2 for object and signing requests,
	// 3 for a credential the service asked to wait for.
	Retries int
	// Backoff is the wait before retry retryCount, counted from 0. A Retry-After from the service
	// wins over it. Nil is full jitter doubling from 200 ms and capped at 4 s, and 2 s for a
	// credential.
	Backoff func(retryCount int) time.Duration
}

// retryPolicy is RetryConfig resolved: retries < 0 means the caller's default for that loop.
type retryPolicy struct {
	retries int
	backoff func(retryCount int) time.Duration
}

func resolveRetry(c RetryConfig) (retryPolicy, error) {
	if c.Retries < 0 {
		return retryPolicy{}, fmt.Errorf("blob: Retry.Retries: expected 0 or more, got %d", c.Retries)
	}
	p := retryPolicy{retries: -1, backoff: c.Backoff}
	if c.Disabled {
		p.retries = 0
	} else if c.Retries > 0 {
		p.retries = c.Retries
	}
	return p, nil
}

func (p retryPolicy) retriesOr(def int) int {
	if p.retries < 0 {
		return def
	}
	return p.retries
}

// retryAfterSeconds parses a numeric Retry-After. A date or anything else is not one.
func retryAfterSeconds(v string) (float64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return 0, false
	}
	return n, true
}

// backoff is full jitter, doubling from base per attempt and capped at 4 s; a Retry-After wins,
// capped at 10 s.
func backoff(attempt int, retryAfter string, base time.Duration) time.Duration {
	if secs, ok := retryAfterSeconds(retryAfter); ok {
		return min(time.Duration(secs*float64(time.Second)), 10*time.Second)
	}
	ceiling := base << min(attempt, 20)
	ceiling = min(ceiling, 4*time.Second)
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(ceiling)))
}

// sleep waits d, or until ctx is done, which it reports.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type tempCredentials struct {
	AccessKeyID     string  `json:"accessKeyId"`
	SecretAccessKey string  `json:"secretAccessKey"`
	SessionToken    string  `json:"sessionToken"`
	Endpoint        string  `json:"endpoint"`
	Bucket          string  `json:"bucket"`
	Region          string  `json:"region"`
	ExpiresAt       float64 `json:"expiresAt"` // Unix seconds.
	// "private" means the bucket has no public host, so a BlobObject carries no URL.
	Visibility string `json:"visibility"`
}

func (c *tempCredentials) expiry() time.Time {
	return time.UnixMilli(int64(c.ExpiresAt * 1000))
}

const (
	// Must stay under the agent's 60 s re-mint margin: at or above it the agent hands back the same
	// credential the SDK already considers stale, and every operation refetches until it is rate limited.
	refreshMargin = 30 * time.Second
	mintTimeout   = 10 * time.Second
	// A Retry-After longer than this is the agent asking for a pause no request can wait out.
	maxMintWait = 10.0
	mintRetries = 3
)

type mintCall struct {
	done  chan struct{}
	creds *tempCredentials
	err   error
}

// credentialCache holds one token's temporary credential. Buckets on one token share it, so a
// bucket built per request does not mint a credential per request.
type credentialCache struct {
	token     string
	telemetry bool

	mu        sync.Mutex
	current   *tempCredentials
	refreshAt time.Time
	inflight  *mintCall
}

// get returns the cached credential or joins a mint. The mint runs detached from ctx, since every
// request on the token shares it; a cancelled ctx only stops this caller waiting.
//
// The mint is sent with the client of the bucket that started it.
func (c *credentialCache) get(ctx context.Context, client *http.Client, retry retryPolicy) (*tempCredentials, error) {
	c.mu.Lock()
	if c.current != nil && time.Now().Before(c.refreshAt) {
		cur := c.current
		c.mu.Unlock()
		return cur, nil
	}
	call := c.inflight
	if call == nil {
		call = &mintCall{done: make(chan struct{})}
		c.inflight = call
		go func() {
			creds, err := c.mint(client, retry)
			c.mu.Lock()
			if err == nil {
				c.current = creds
				refresh := creds.expiry().Add(-refreshMargin)
				if now := time.Now(); refresh.Before(now) {
					refresh = now
				}
				c.refreshAt = refresh
			}
			c.inflight = nil
			call.creds, call.err = creds, err
			c.mu.Unlock()
			close(call.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-call.done:
		return call.creds, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// peek is the cached credential without minting one; nil before the first mint.
func (c *credentialCache) peek() *tempCredentials {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// invalidate drops the credential after a 403 that named it, so the next get mints. Given the
// credential the request was signed with, a newer one is kept: parts refused together re-mint once.
func (c *credentialCache) invalidate(stale *tempCredentials) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if stale != nil && c.current != stale {
		return
	}
	c.current = nil
	c.refreshAt = time.Time{}
}

func (c *credentialCache) mint(client *http.Client, retry retryPolicy) (*tempCredentials, error) {
	for attempt := 0; ; attempt++ {
		res, err := c.post(client)
		if err != nil {
			// A plain error, not an *Error: the request loop retries it as a dropped connection.
			return nil, fmt.Errorf("blob: credentials request: %w", err)
		}
		if res.StatusCode == 429 || res.StatusCode == 503 {
			parsed, given := retryAfterSeconds(res.Header.Get("Retry-After"))
			given = given && parsed > 0
			asked := 2.0
			if given {
				asked = parsed
			}
			drain(res)
			if asked > maxMintWait {
				return nil, NewError(CodeMintBackoff, ErrorOptions{
					Message:    fmt.Sprintf("the credential service asked for %ss of backoff", strconv.FormatFloat(asked, 'f', -1, 64)),
					RetryAfter: time.Duration(asked * float64(time.Second)),
				})
			}
			if attempt < retry.retriesOr(mintRetries) {
				wait := time.Duration(asked * float64(time.Second))
				if !given && retry.backoff != nil {
					wait = max(retry.backoff(attempt), 0)
				}
				time.Sleep(wait)
				continue
			}
		}
		defer drain(res)
		switch {
		case res.StatusCode == 401:
			return nil, newErr(CodeUnauthorized, "the bucket token was rejected")
		case res.StatusCode == 429:
			return nil, newErr(CodeRateLimited, "credential requests are rate limited")
		case res.StatusCode == 503:
			return nil, NewError(CodeNotReady, ErrorOptions{})
		case res.StatusCode < 200 || res.StatusCode > 299:
			return nil, NewError(CodeRequestFailed, ErrorOptions{Message: fmt.Sprintf("credentials request failed with %d", res.StatusCode), Status: 502})
		}
		var creds tempCredentials
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&creds); err != nil {
			return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "credentials response was not JSON", Status: 502, Cause: err})
		}
		// The endpoint decides where every object request goes: refuse anything but R2 over https.
		if !isR2URL(creds.Endpoint) {
			return nil, NewError(CodeRequestFailed, ErrorOptions{Message: "credentials response named an unexpected endpoint", Status: 502})
		}
		creds.Endpoint = strings.TrimRight(creds.Endpoint, "/")
		if creds.Visibility != "public" && creds.Visibility != "private" {
			creds.Visibility = ""
		}
		if creds.Region == "" {
			creds.Region = "auto"
		}
		return &creds, nil
	}
}

func (c *credentialCache) post(client *http.Client) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mintTimeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, agentURL+"/v1/credentials", nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	for k, v := range telemetryHeaders(c.telemetry) {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	res.Body = cancelOnClose{res.Body, cancel}
	return res, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// isR2URL is https on a *.r2.cloudflarestorage.com host.
func isR2URL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && strings.HasSuffix(u.Hostname(), ".r2.cloudflarestorage.com") && u.User == nil
}

// drain reads off what is left of a body so the connection is reused, then closes it.
func drain(res *http.Response) {
	if res == nil || res.Body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, res.Body, 64<<10)
	_ = res.Body.Close()
}

var (
	cachesMu sync.Mutex
	caches   = map[cacheKey]*credentialCache{}
)

type cacheKey struct {
	token     string
	telemetry bool
}

// credentialCacheFor is keyed by token rather than held per Bucket: a bucket built per request is
// the documented shape on serverless platforms, and an instance-held cache minted for each one.
func credentialCacheFor(token string, telemetry bool) *credentialCache {
	cachesMu.Lock()
	defer cachesMu.Unlock()
	k := cacheKey{token, telemetry}
	c, ok := caches[k]
	if !ok {
		c = &credentialCache{token: token, telemetry: telemetry}
		caches[k] = c
	}
	return c
}

func resetCredentialCaches() {
	cachesMu.Lock()
	defer cachesMu.Unlock()
	caches = map[cacheKey]*credentialCache{}
}
