package okta

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/benbjohnson/clock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type FetchStrategy int64

const (
	Lazy FetchStrategy = iota // Fetch new Okta JWT set inline with requests (when not cached)
	// Background Fetch new Okta JWT set in the background regardless of requests being made. This option was designed
	// for eliminating in-line Okta JWK set calls and minimizing latency in production use. Warning: this option will
	// attempt to seed Okta JWT sets on initialization and block.
	Background

	DefaultCacheTtl = 5 * time.Minute
)

// Options are configurable options for the KeyfuncProvider.
type Options struct {
	httpClient    *http.Client
	clock         clock.Clock
	cacheTtl      time.Duration
	fetchStrategy FetchStrategy
	backgroundCtx context.Context
}

// WithHttpClient allows for a configurable http client.
func WithHttpClient(httpClient *http.Client) Option {
	return func(mo *Options) {
		mo.httpClient = httpClient
	}
}

func withClock(clock clock.Clock) Option {
	return func(mo *Options) {
		mo.clock = clock
	}
}

// WithCacheTtl specifies the TTL on the Okta JWK set.
func WithCacheTtl(ttl time.Duration) Option {
	return func(mo *Options) {
		mo.cacheTtl = ttl
	}
}

// WithFetchStrategy specifies a strategy for fetching new Okta JWK sets.
func WithFetchStrategy(fetchStrategy FetchStrategy) Option {
	return func(mo *Options) {
		mo.fetchStrategy = fetchStrategy
	}
}

// WithBackgroundCtx specified the context to use in order to control the lifecycle of the background fetching
// goroutine.
func WithBackgroundCtx(ctx context.Context) Option {
	return func(mo *Options) {
		mo.backgroundCtx = ctx
	}
}

func defaultOptions() *Options {
	opts := &Options{}
	WithHttpClient(http.DefaultClient)(opts)
	withClock(clock.New())(opts)
	WithCacheTtl(DefaultCacheTtl)(opts)
	WithFetchStrategy(Lazy)(opts)
	WithBackgroundCtx(context.Background())(opts)
	return opts
}

// Option for the KeyfuncProvider
type Option func(*Options)

type cachedKeyfunc struct {
	expiration time.Time
	keyfunc    jwt.Keyfunc
}

func newCachedKeyfunc(expiration time.Time, keyfunc jwt.Keyfunc) *cachedKeyfunc {
	return &cachedKeyfunc{expiration: expiration, keyfunc: keyfunc}
}

// KeyfuncProvider implements the keyfunc.KeyfuncProvider and generates JWT validating functions for Okta tokens.
type KeyfuncProvider struct {
	mp         metadata.Provider
	httpClient *http.Client
	clock      clock.Clock

	keyfuncMutex  sync.Mutex
	cacheTtl      time.Duration
	cachedKeyfunc *cachedKeyfunc
	fetchStrategy FetchStrategy
}

// NewKeyfuncProvider creates a new KeyfuncProvider.
func NewKeyfuncProvider(mp metadata.Provider, options ...Option) (*KeyfuncProvider, error) {
	opts := defaultOptions()
	for _, option := range options {
		option(opts)
	}

	kp := &KeyfuncProvider{
		mp:            mp,
		httpClient:    opts.httpClient,
		clock:         opts.clock,
		cacheTtl:      opts.cacheTtl,
		fetchStrategy: opts.fetchStrategy,
	}

	if opts.fetchStrategy == Background {
		md, err := kp.mp.GetMetadata(opts.backgroundCtx)
		if err != nil {
			return nil, fmt.Errorf("getting metadata: %w", err)
		}

		_, err = kp.backgroundFetchAndCache(opts.backgroundCtx, md.JwksUri)
		if err != nil {
			return nil, fmt.Errorf("failed to seed Okta JWK set: %w", err)
		}
		go kp.backgroundFetchLoop(opts.backgroundCtx)
	}

	return kp, nil
}

// GetKeyfunc gets a jwt.Keyfunc based on the OIDC metadata.
func (kp *KeyfuncProvider) GetKeyfunc(ctx context.Context) (jwt.Keyfunc, error) {
	md, err := kp.mp.GetMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}

	kf, err := kp.lazyFetchAndCache(ctx, md.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("getting or fetching keyfunc: %w", err)
	}

	return kf, nil
}

func (kp *KeyfuncProvider) lazyFetchAndCache(ctx context.Context, jwksUri string) (jwt.Keyfunc, error) {
	cachedKeyfuncCopy := kp.cachedKeyfunc

	if cachedKeyfuncCopy != nil && kp.clock.Now().Before(cachedKeyfuncCopy.expiration) {
		return cachedKeyfuncCopy.keyfunc, nil
	}

	// Acquire a lock
	kp.keyfuncMutex.Lock()
	defer kp.keyfuncMutex.Unlock()

	// Check again to protect against races
	cachedKeyfuncCopy = kp.cachedKeyfunc

	if cachedKeyfuncCopy != nil && kp.clock.Now().Before(cachedKeyfuncCopy.expiration) {
		return cachedKeyfuncCopy.keyfunc, nil
	}

	kf, err := kp.fetchKeyfunc(ctx, jwksUri)
	if err != nil {
		return nil, fmt.Errorf("fetching keyfunc: %w", err)
	}

	expiration := kp.clock.Now().Add(kp.cacheTtl)
	kp.cachedKeyfunc = newCachedKeyfunc(expiration, kf)

	return kf, nil
}

func (kp *KeyfuncProvider) backgroundFetchAndCache(ctx context.Context, jwksUri string) (jwt.Keyfunc, error) {
	// Acquire a lock
	kp.keyfuncMutex.Lock()
	defer kp.keyfuncMutex.Unlock()

	expiration := kp.clock.Now().Add(kp.cacheTtl)

	newKeyfunc, err := kp.fetchKeyfunc(ctx, jwksUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch new fresh key func: %w", err)
	}
	kp.cachedKeyfunc = newCachedKeyfunc(expiration, newKeyfunc)
	return kp.cachedKeyfunc.keyfunc, nil
}

func (kp *KeyfuncProvider) backgroundFetchLoop(ctx context.Context) {
	ticker := kp.clock.Ticker(kp.cacheTtl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			md, err := kp.mp.GetMetadata(ctx)
			if err != nil {
				slog.ErrorContext(ctx, fmt.Sprintf("failed to fetch and cache metadata: %s", err.Error()))
			}
			_, err = kp.backgroundFetchAndCache(ctx, md.JwksUri)
			if err != nil {
				slog.ErrorContext(ctx, fmt.Sprintf("failed to fetch and cache key func: %s", err.Error()))
			}
		}
	}
}

func (kp *KeyfuncProvider) fetchKeyfunc(ctx context.Context, jwksUri string) (jwt.Keyfunc, error) {

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksUri, nil)
	if err != nil {
		return nil, fmt.Errorf("creating new http request: %w", err)
	}
	resp, err := kp.httpClient.Do(httpRequest)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("making http request for jwks: %w", err)
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return nil, fmt.Errorf("request for jwks %q was not HTTP 2xx OK, it was: %d", jwksUri, resp.StatusCode)
	}

	jwkJson, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jwks response body: %w", err)
	}

	kf, err := keyfunc.NewJWKSetJSON(jwkJson)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyfunc from jwk json: %w", err)
	}

	return kf.Keyfunc, nil

}
