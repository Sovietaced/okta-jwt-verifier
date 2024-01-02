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

// Option for the OktaMetadataProvider
type Option func(*Options)

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
func (v *Verifier) VerifyIdToken(ctx context.Context, idToken string) (*jwt.Token, error) {
	jwt, err := v.parseToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id token: %w", err)
	}

	claims := jwt.Claims

	jwtIssuer, err := claims.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("verifying id token issuer: %w", err)
	}

	if jwtIssuer != v.issuer {
		return nil, fmt.Errorf("verifying id token issuer: issuer '%s' in token does not match '%s'", jwtIssuer, v.issuer)
	}

	jwtAuds, err := claims.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("veriying id token audience: %w", err)
	}

	matchFound := false
	for _, jwtAud := range jwtAuds {
		if jwtAud == v.clientId {
			matchFound = true
			break
		}
	}

	if !matchFound {
		return nil, fmt.Errorf("verifying id token audience: audience '%s' in token does not match '%s'", jwtAuds, v.clientId)
	}

	jwtIat, err := claims.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("verifying id token issued time: %w", err)
	}

	if jwtIat == nil {
		return nil, fmt.Errorf("verifying id token issued time: no issued time found")
	}

	jwtExp, err := claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("verifying id token expriation time: %w", err)
	}

	if jwtExp == nil {
		return nil, fmt.Errorf("verifying id token expiration time: no expiration time found")
	}

	// FIXME: add support for nonce

	return jwt, nil
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
