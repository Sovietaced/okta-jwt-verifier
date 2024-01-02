package verifier

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc/okta"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc/okta/oktatest"
	"github.com/sovietaced/okta-jwt-verifier/metadata"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestVerifier(t *testing.T) {
	issuer := "https://test.okta.com"
	clientId := "test"

	// Generate RSA key.
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	ctx := context.Background()

	uri, _ := oktatest.ServeJwks(t, ctx, pk)

	mp := &oktatest.StaticMetadataProvider{
		Md: metadata.Metadata{
			JwksUri: uri,
		},
	}

	kp := okta.NewKeyfuncProvider(mp)
	v := NewVerifier(issuer, clientId, WithKeyfuncProvider(kp))

	t.Run("verify valid id token", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"aud": clientId,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.NoError(t, err)
	})

	t.Run("verify id token missing issuer", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"aud": clientId,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.ErrorContains(t, err, "verifying id token issuer: issuer '' in token does not match 'https://test.okta.com'")
	})

	t.Run("verify id token missing audience", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.ErrorContains(t, err, "verifying id token audience: audience '[]' in token does not match 'test'")
	})

	t.Run("verify id token missing issued time", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"aud": clientId,
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.ErrorContains(t, err, "verifying id token issued time: no issued time found")
	})

	t.Run("verify id token missing expiration", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"aud": clientId,
			"iat": time.Now().Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.ErrorContains(t, err, "verifying id token expiration time: no expiration time found")
	})

	t.Run("verify id token expired", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer,
			"aud": clientId,
			"iat": time.Now().Unix(),
			"exp": time.Now().Unix(),
		})
		token.Header["kid"] = oktatest.KID
		idToken, err := token.SignedString(pk)
		require.NoError(t, err)

		_, err = v.VerifyIdToken(ctx, idToken)
		require.ErrorContains(t, err, "verifying id token: parsing token: token has invalid claims: token is expired")
	})
}
