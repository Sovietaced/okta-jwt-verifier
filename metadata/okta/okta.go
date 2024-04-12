package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/benbjohnson/clock"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type FetchStrategy int64

const (
	Lazy FetchStrategy = iota // Fetch new metadata inline with requests (when not cached)
	// Background Fetch new metadata in the background regardless of requests being made. This option was designed
	// for eliminating in-line metadata calls and minimizing latency in production use. Warning: this option will
	// attempt to seed metadata on initialization and block.
	Background

	DefaultCacheTtl = 5 * time.Minute
)

// Options are configurable options for the MetadataProvider.
type Options struct {
	httpClient    *http.Client
	cacheTtl      time.Duration
	clock         clock.Clock
	fetchStrategy FetchStrategy
	backgroundCtx context.Context
}

// WithHttpClient allows for a configurable http client.
func WithHttpClient(httpClient *http.Client) Option {
	return func(mo *Options) {
		mo.httpClient = httpClient
	}
}

// WithCacheTtl specifies the TTL on the Okta JWK set.
func WithCacheTtl(ttl time.Duration) Option {
	return func(mo *Options) {
		mo.cacheTtl = ttl
	}
}

func withClock(clock clock.Clock) Option {
	return func(mo *Options) {
		mo.clock = clock
	}
}

// WithFetchStrategy specifies a strategy for fetching new metadata.
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

// Option for the MetadataProvider.
type Option func(*Options)

type cachedMetadata struct {
	expiration time.Time
	m          metadata.Metadata
}

func newCachedMetadata(expiration time.Time, m metadata.Metadata) *cachedMetadata {
	return &cachedMetadata{expiration: expiration, m: m}
}

// MetadataProvider is an implementation of metadata.Provider that retrieves metadata from Okta's well known openid
// configuration
type MetadataProvider struct {
	metadataUrl string       // The URL to use to retrieve metadata
	httpClient  *http.Client // the HTTP client to use to retrieve metadata
	clock       clock.Clock

	metadataMutex  sync.Mutex
	cacheTtl       time.Duration
	cachedMetadata *cachedMetadata
	fetchStrategy  FetchStrategy
}

// NewMetadataProvider creates a new MetadataProvider for the specified Okta issuer.
func NewMetadataProvider(issuer string, options ...Option) (*MetadataProvider, error) {
	opts := defaultOptions()
	for _, option := range options {
		option(opts)
	}

	metadataUrl := fmt.Sprintf("%s%s", issuer, "/.well-known/openid-configuration")
	mp := &MetadataProvider{
		metadataUrl:   metadataUrl,
		httpClient:    opts.httpClient,
		clock:         opts.clock,
		cacheTtl:      opts.cacheTtl,
		fetchStrategy: opts.fetchStrategy,
	}

	if opts.fetchStrategy == Background {
		_, err := mp.backgroundFetchAndCache(opts.backgroundCtx)
		if err != nil {
			return nil, fmt.Errorf("failed to seed metadata: %w", err)
		}
		go mp.backgroundFetchLoop(opts.backgroundCtx)
	}

	return mp, nil
}

// GetMetadata gets metadata for the specified Okta issuer.
func (mp *MetadataProvider) GetMetadata(ctx context.Context) (metadata.Metadata, error) {

	cachedMetadataCopy := mp.cachedMetadata

	if cachedMetadataCopy != nil && mp.clock.Now().Before(cachedMetadataCopy.expiration) {
		return cachedMetadataCopy.m, nil
	}

	if mp.fetchStrategy == Lazy {
		return mp.lazyFetchAndCache(ctx)
	} else if mp.fetchStrategy == Background {
		// FIXME: Potentially make this behavior configurable?
		return cachedMetadataCopy.m, nil
	}

	return metadata.Metadata{}, fmt.Errorf("no metadata available")

}

func (mp *MetadataProvider) lazyFetchAndCache(ctx context.Context) (metadata.Metadata, error) {
	// Acquire a lock
	mp.metadataMutex.Lock()
	defer mp.metadataMutex.Unlock()

	// Check for a race before continuing
	cachedMetadataCopy := mp.cachedMetadata
	if cachedMetadataCopy != nil && mp.clock.Now().Before(cachedMetadataCopy.expiration) {
		return cachedMetadataCopy.m, nil
	}

	expiration := mp.clock.Now().Add(mp.cacheTtl)

	newMetadata, err := mp.fetchMetadata(ctx)
	if err != nil {
		return metadata.Metadata{}, fmt.Errorf("failed to fetch new fresh metadata: %w", err)
	}

	mp.cachedMetadata = newCachedMetadata(expiration, newMetadata)
	return mp.cachedMetadata.m, nil
}

func (mp *MetadataProvider) backgroundFetchAndCache(ctx context.Context) (metadata.Metadata, error) {
	// Acquire a lock
	mp.metadataMutex.Lock()
	defer mp.metadataMutex.Unlock()

	expiration := mp.clock.Now().Add(mp.cacheTtl)

	newMetadata, err := mp.fetchMetadata(ctx)
	if err != nil {
		return metadata.Metadata{}, fmt.Errorf("failed to fetch new fresh metadata: %w", err)
	}

	mp.cachedMetadata = newCachedMetadata(expiration, newMetadata)
	return mp.cachedMetadata.m, nil
}

func (mp *MetadataProvider) backgroundFetchLoop(ctx context.Context) {
	// Seed cache initially
	_, err := mp.backgroundFetchAndCache(ctx)
	if err != nil {
		slog.ErrorContext(ctx, fmt.Sprintf("failed to fetch and cache metadata: %s", err.Error()))
	}

	ticker := time.NewTicker(mp.cacheTtl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, err := mp.backgroundFetchAndCache(ctx)
			if err != nil {
				slog.ErrorContext(ctx, fmt.Sprintf("failed to fetch and cache metadata: %s", err.Error()))
			}
		}
	}
}

func (mp *MetadataProvider) fetchMetadata(ctx context.Context) (metadata.Metadata, error) {
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, mp.metadataUrl, nil)
	if err != nil {
		return metadata.Metadata{}, fmt.Errorf("creating new http request: %w", err)
	}
	resp, err := mp.httpClient.Do(httpRequest)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return metadata.Metadata{}, fmt.Errorf("making http request for metadata: %w", err)
	}

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !ok {
		return metadata.Metadata{}, fmt.Errorf("request for metadata %q was not HTTP 2xx OK, it was: %d", mp.metadataUrl, resp.StatusCode)
	}

	m := metadata.Metadata{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, fmt.Errorf("decoding metadata: %w", err)
	}

	return m, nil
}
