package okta

import (
	"context"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/benbjohnson/clock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"io"
	"net/http"
	"sync"
	"time"
)

// Options are configurable options for the KeyfuncProvider.
type Options struct {
	httpClient *http.Client
	clock      clock.Clock
	cacheTtl   time.Duration
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

func defaultOptions() *Options {
	opts := &Options{}
	WithHttpClient(http.DefaultClient)(opts)
	withClock(clock.New())(opts)
	WithCacheTtl(5 * time.Minute)(opts)
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
}

// NewKeyfuncProvider creates a new KeyfuncProvider.
func NewKeyfuncProvider(mp metadata.Provider, options ...Option) *KeyfuncProvider {
	opts := defaultOptions()
	for _, option := range options {
		option(opts)
	}

	return &KeyfuncProvider{mp: mp, httpClient: opts.httpClient, clock: opts.clock, cacheTtl: opts.cacheTtl}
}

// GetKeyfunc gets a jwt.Keyfunc based on the OIDC metadata.
func (kp *KeyfuncProvider) GetKeyfunc(ctx context.Context) (jwt.Keyfunc, error) {
	md, err := kp.mp.GetMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}

	keyfunc, err := kp.getOrFetchKeyfunc(ctx, md.JwksUri)
	if err != nil {
		return nil, fmt.Errorf("getting or fetching keyfunc: %w", err)
	}

	return keyfunc, nil
}

func (kp *KeyfuncProvider) getOrFetchKeyfunc(ctx context.Context, jwksUri string) (jwt.Keyfunc, error) {
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

	keyfunc, err := kp.fetchKeyfunc(ctx, jwksUri)
	if err != nil {
		return nil, fmt.Errorf("fetching keyfunc: %w", err)
	}

	expiration := kp.clock.Now().Add(kp.cacheTtl)
	kp.cachedKeyfunc = newCachedKeyfunc(expiration, keyfunc)

	return keyfunc, nil
}

func (kp *KeyfuncProvider) fetchKeyfunc(ctx context.Context, jwksUri string) (jwt.Keyfunc, error) {

	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksUri, nil)
	if err != nil {
		return nil, fmt.Errorf("creating new http request: %w", err)
	}
	resp, err := kp.httpClient.Do(httpRequest)
	if err != nil {
		return nil, fmt.Errorf("making http request for jwks: %w", err)
	}
	defer resp.Body.Close()

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
