package verifier

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc/okta"
	oktametadata "github.com/sovietaced/okta-jwt-verifier/metadata/okta"
)

// Options are configurable options for the Verifier.
type Options struct {
	keyfuncProvider keyfunc.Provider
}

// WithKeyfuncProvider allows for a configurable keyfunc.Provider, which may be useful if you want to customize
// the behavior of how metadata or JWK sets are fetched.
func WithKeyfuncProvider(keyfuncProvider keyfunc.Provider) Option {
	return func(mo *Options) {
		mo.keyfuncProvider = keyfuncProvider
	}
}

func defaultOptions(issuer string) *Options {
	opts := &Options{}
	WithKeyfuncProvider(okta.NewKeyfuncProvider(oktametadata.NewMetadataProvider(issuer)))(opts)
	return opts
}

// Option for the Verifier
type Option func(*Options)

// Jwt is an implementation independent representation of a JWT that is returned to consumers of our APIs.
type Jwt struct {
	Claims map[string]any
}

// newJwtFromToken creates our Jwt struct from a jwt.Token.
func newJwtFromToken(token *jwt.Token) *Jwt {
	claims := token.Claims.(jwt.MapClaims)
	return &Jwt{Claims: claims}
}

// Verifier is the implementation of the Okta JWT verification logic.
type Verifier struct {
	keyfuncProvider keyfunc.Provider
	issuer          string
	clientId        string
}

// NewVerifier creates a new Verifier for the specified issuer or client ID.
func NewVerifier(issuer string, clientId string, options ...Option) *Verifier {
	opts := defaultOptions(issuer)
	for _, option := range options {
		option(opts)
	}

	return &Verifier{issuer: issuer, clientId: clientId, keyfuncProvider: opts.keyfuncProvider}
}

// VerifyIdToken verifies an Okta ID token.
func (v *Verifier) VerifyIdToken(ctx context.Context, idToken string) (*Jwt, error) {
	token, err := v.parseToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id token: %w", err)
	}

	if err = v.validateCommonClaims(ctx, token); err != nil {
		return nil, fmt.Errorf("validating claims: %w", err)
	}

	claims := token.Claims.(jwt.MapClaims)

	_, exists := claims["nonce"]
	if !exists {
		return nil, fmt.Errorf("verifying token nonce: no nonce found")
	}

	return newJwtFromToken(token), nil
}

// VerifyAccessToken verifies an Okta access token.
func (v *Verifier) VerifyAccessToken(ctx context.Context, accessToken string) (*Jwt, error) {
	token, err := v.parseToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("verifying access token: %w", err)
	}

	if err = v.validateCommonClaims(ctx, token); err != nil {
		return nil, fmt.Errorf("validating claims: %w", err)
	}

	return newJwtFromToken(token), nil
}

func (v *Verifier) parseToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	keyfunc, err := v.keyfuncProvider.GetKeyfunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting key function: %w", err)
	}

	token, err := jwt.Parse(tokenString, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	return token, err
}

func (v *Verifier) validateCommonClaims(ctx context.Context, jwt *jwt.Token) error {
	claims := jwt.Claims

	jwtIssuer, err := claims.GetIssuer()
	if err != nil {
		return fmt.Errorf("verifying token issuer: %w", err)
	}

	if jwtIssuer != v.issuer {
		return fmt.Errorf("verifying token issuer: issuer '%s' in token does not match '%s'", jwtIssuer, v.issuer)
	}

	jwtAuds, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("veriying token audience: %w", err)
	}

	matchFound := false
	for _, jwtAud := range jwtAuds {
		if jwtAud == v.clientId {
			matchFound = true
			break
		}
	}

	if !matchFound {
		return fmt.Errorf("verifying token audience: audience '%s' in token does not match '%s'", jwtAuds, v.clientId)
	}

	jwtIat, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("verifying id token issued time: %w", err)
	}

	if jwtIat == nil {
		return fmt.Errorf("verifying token issued time: no issued time found")
	}

	jwtExp, err := claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("verifying token expriation time: %w", err)
	}

	if jwtExp == nil {
		return fmt.Errorf("verifying token expiration time: no expiration time found")
	}

	return nil
}
