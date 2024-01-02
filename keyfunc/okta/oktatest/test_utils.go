package oktatest

import (
	"context"
	"crypto/rsa"
	"github.com/MicahParks/jwkset"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	KID = "test"
)

type StaticMetadataProvider struct {
	Md metadata.Metadata
}

func (smp *StaticMetadataProvider) GetMetadata(ctx context.Context) (metadata.Metadata, error) {
	return smp.Md, nil
}

func ServeJwks(t *testing.T, ctx context.Context, priv *rsa.PrivateKey) (string, func() int) {
	serverStore := jwkset.NewMemoryStorage()
	md := jwkset.JWKMetadataOptions{
		KID: KID,
	}
	jwkOptions := jwkset.JWKOptions{
		Metadata: md,
	}
	jwk, err := jwkset.NewJWKFromKey(priv, jwkOptions)
	require.NoError(t, err)

	err = serverStore.KeyWrite(ctx, jwk)
	require.NoError(t, err)

	rawJWKS, err := serverStore.JSONPrivate(ctx)
	require.NoError(t, err)

	count := 0
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.Write(rawJWKS)
	}))
	t.Cleanup(svr.Close)

	return svr.URL, func() int { return count }
}
