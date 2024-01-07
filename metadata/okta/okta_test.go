package okta

import (
	"context"
	"fmt"
	"github.com/benbjohnson/clock"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/otel/propagation"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestLazyMetadataProvider(t *testing.T) {

	ctx := context.Background()

	t.Run("get metadata success", func(t *testing.T) {
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(fixture(t, "metadata.json"))
		}))
		defer svr.Close()

		mp, err := NewMetadataProvider(svr.URL)
		require.NoError(t, err)

		m, err := mp.GetMetadata(ctx)
		require.NoError(t, err)

		expectedMetadata := metadata.Metadata{JwksUri: "https://test.okta.com/oauth2/v1/keys"}
		require.Equal(t, expectedMetadata, m)
	})

	t.Run("get metadata and verify cached", func(t *testing.T) {
		serverCount := 0
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCount++
			w.Write(fixture(t, "metadata.json"))
		}))
		defer svr.Close()

		fakeClock := clock.NewMock()
		mp, err := NewMetadataProvider(svr.URL, withClock(fakeClock))
		require.NoError(t, err)

		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, serverCount)

		// Get metadata again and ensure it is cached
		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, serverCount)

		// Fast forward time and invalidate the cache
		fakeClock.Add(10 * time.Minute)

		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, serverCount)
	})

	t.Run("get metadata and verify tracing", func(t *testing.T) {
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(fixture(t, "metadata.json"))
		}))
		defer svr.Close()

		prop := propagation.TraceContext{}
		spanRecorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))

		tr := otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithTracerProvider(provider),
			otelhttp.WithPropagators(prop),
		)

		httpClient := http.Client{Transport: tr}
		mp, err := NewMetadataProvider(svr.URL, WithHttpClient(&httpClient))
		require.NoError(t, err)

		tracer := provider.Tracer("test")
		spanCtx, span := tracer.Start(ctx, "test")
		_, err = mp.GetMetadata(spanCtx)
		require.NoError(t, err)
		span.End()

		spans := spanRecorder.Ended()
		require.Len(t, spans, 2)
		httpSpan := spans[0]
		require.Equal(t, "HTTP GET", httpSpan.Name())

		testSpan := spans[1]
		require.Equal(t, "test", testSpan.Name())

		// Verify trace propagation through context
		require.Equal(t, testSpan.SpanContext().SpanID(), httpSpan.Parent().SpanID())
	})
}

func TestBackgroundMetadataProvider(t *testing.T) {

	ctx := context.Background()

	t.Run("get metadata success", func(t *testing.T) {
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(fixture(t, "metadata.json"))
		}))
		defer svr.Close()

		backgroundCtx, cancelFunc := context.WithCancel(ctx)
		defer cancelFunc()

		mp, err := NewMetadataProvider(svr.URL, WithFetchStrategy(Background), WithBackgroundCtx(backgroundCtx))
		require.NoError(t, err)

		m, err := mp.GetMetadata(ctx)
		require.NoError(t, err)

		expectedMetadata := metadata.Metadata{JwksUri: "https://test.okta.com/oauth2/v1/keys"}
		require.Equal(t, expectedMetadata, m)
	})

	t.Run("get metadata and verify cached", func(t *testing.T) {
		serverCount := 0
		svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			serverCount++
			w.Write(fixture(t, "metadata.json"))
		}))
		defer svr.Close()

		backgroundCtx, cancelFunc := context.WithCancel(ctx)
		defer cancelFunc()

		fakeClock := clock.NewMock()
		mp, err := NewMetadataProvider(svr.URL, withClock(fakeClock), WithFetchStrategy(Background), WithBackgroundCtx(backgroundCtx))
		require.NoError(t, err)

		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, serverCount)

		// Get metadata again and ensure it is cached
		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, serverCount)

		// Fast forward time and invalidate the cache
		fakeClock.Add(10 * time.Minute)

		_, err = mp.GetMetadata(ctx)
		require.NoError(t, err)
		require.Equal(t, 2, serverCount)
	})
}

func fixture(t *testing.T, filename string) []byte {
	b, err := os.ReadFile(fmt.Sprintf("testdata/%s", filename))
	if err != nil {
		t.Fatal(err)
	}

	return b
}
