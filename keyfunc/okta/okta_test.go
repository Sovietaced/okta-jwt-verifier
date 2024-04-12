package okta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	clock2 "github.com/benbjohnson/clock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc/okta/oktatest"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"net/http"
	"testing"
	"time"
)

func TestLazyKeyfuncProvider(t *testing.T) {

	// Generate RSA key.
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("get keyfunc", func(t *testing.T) {
		uri, _ := oktatest.ServeJwks(t, ctx, pk)

		mp := &oktatest.StaticMetadataProvider{
			Md: metadata.Metadata{
				JwksUri: uri,
			},
		}

		kp, err := NewKeyfuncProvider(mp)
		require.NoError(t, err)

		keyfunc, err := kp.GetKeyfunc(ctx)
		require.NoError(t, err)
		validateKeyfunc(t, keyfunc, pk)
	})

	t.Run("get keyfunc and verify cached", func(t *testing.T) {
		uri, countFun := oktatest.ServeJwks(t, ctx, pk)

		mp := &oktatest.StaticMetadataProvider{
			Md: metadata.Metadata{
				JwksUri: uri,
			},
		}

		clock := clock2.NewMock()
		kp, err := NewKeyfuncProvider(mp, withClock(clock))
		require.NoError(t, err)

		keyfunc, err := kp.GetKeyfunc(ctx)
		require.NoError(t, err)
		validateKeyfunc(t, keyfunc, pk)
		require.Equal(t, 1, countFun())

		// Get again and verify that it was cached
		keyfunc, err = kp.GetKeyfunc(ctx)
		require.NoError(t, err)
		validateKeyfunc(t, keyfunc, pk)
		require.Equal(t, 1, countFun())

		// Fast forward time and invalidate cache
		clock.Add(10 * time.Minute)
		keyfunc, err = kp.GetKeyfunc(ctx)
		require.NoError(t, err)
		validateKeyfunc(t, keyfunc, pk)
		require.Equal(t, 2, countFun())
	})

	t.Run("get keyfunc and validate tracing", func(t *testing.T) {
		prop := propagation.TraceContext{}
		spanRecorder := tracetest.NewSpanRecorder()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))

		tr := otelhttp.NewTransport(
			http.DefaultTransport,
			otelhttp.WithTracerProvider(provider),
			otelhttp.WithPropagators(prop),
		)

		httpClient := http.Client{Transport: tr}

		uri, _ := oktatest.ServeJwks(t, ctx, pk)

		mp := &oktatest.StaticMetadataProvider{
			Md: metadata.Metadata{
				JwksUri: uri,
			},
		}

		kp, err := NewKeyfuncProvider(mp, WithHttpClient(&httpClient))
		require.NoError(t, err)

		tracer := provider.Tracer("test")
		spanCtx, span := tracer.Start(ctx, "test")

		keyfunc, err := kp.GetKeyfunc(spanCtx)
		require.NoError(t, err)
		span.End()
		validateKeyfunc(t, keyfunc, pk)

		spans := spanRecorder.Ended()
		require.Len(t, spans, 2)
		httpSpan := spans[0]
		require.Equal(t, "HTTP GET", httpSpan.Name())

		testSpan := spans[1]
		require.Equal(t, "test", testSpan.Name())

		// Verify trace propagation through context
		require.Equal(t, testSpan.SpanContext().SpanID(), httpSpan.Parent().SpanID())
	})

	t.Run("get keyfunc and metadata provider returns error", func(t *testing.T) {
		mp := errorMetadataProvider{err: fmt.Errorf("synthetic error")}

		kp, err := NewKeyfuncProvider(&mp)
		require.NoError(t, err)

		_, err = kp.GetKeyfunc(ctx)
		require.ErrorContains(t, err, "getting metadata: synthetic error")
	})

	t.Run("get keyfunc and jwks uri is invalid", func(t *testing.T) {
		mp := &oktatest.StaticMetadataProvider{
			Md: metadata.Metadata{
				JwksUri: "bad",
			},
		}

		kp, err := NewKeyfuncProvider(mp)
		require.NoError(t, err)

		_, err = kp.GetKeyfunc(ctx)
		require.Error(t, err)
		require.ErrorContains(t, err, "getting or fetching keyfunc: fetching keyfunc: making http request for jwks")
	})
}

func validateKeyfunc(t *testing.T, keyfunc jwt.Keyfunc, pk *rsa.PrivateKey) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{})
	token.Header["kid"] = oktatest.KID
	tokenString, err := token.SignedString(pk)
	require.NoError(t, err)

	_, err = jwt.Parse(tokenString, keyfunc)
	require.NoError(t, err)
}

type errorMetadataProvider struct {
	err error
}

func (emp *errorMetadataProvider) GetMetadata(ctx context.Context) (metadata.Metadata, error) {
	return metadata.Metadata{}, emp.err

}
