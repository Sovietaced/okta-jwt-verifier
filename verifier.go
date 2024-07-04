package verifier

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc"
	"github.com/sovietaced/okta-jwt-verifier/keyfunc/okta"
	oktametadata "github.com/sovietaced/okta-jwt-verifier/metadata/okta"
	"time"
)

const (
	DefaultLeeway = 0 // Default leeway that is configured for JWT validation
)

// Options are configurable options for the Verifier.
type Options struct {
	keyfuncProvider keyfunc.Provider
	leeway          time.Duration
}

// WithKeyfuncProvider allows for a configurable keyfunc.Provider, which may be useful if you want to customize
// the behavior of how metadata or JWK sets are fetched.
func WithKeyfuncProvider(keyfuncProvider keyfunc.Provider) Option {
	return func(mo *Options) {
		mo.keyfuncProvider = keyfuncProvider
	}
}

// WithLeeway adds leeway to all time related validations.
func WithLeeway(leeway time.Duration) Option {
	return func(mo *Options) {
		mo.leeway = leeway
	}
}

func defaultOptions(issuer string) (*Options, error) {
	opts := &Options{}
	mp, err := oktametadata.NewMetadataProvider(issuer)
	if err != nil {
		return nil, fmt.Errorf("creating default metadata provider: %w", err)
	}

	kp, err := okta.NewKeyfuncProvider(mp)
	if err != nil {
		return nil, fmt.Errorf("creating new key func provider: %w", err)
	}
	WithKeyfuncProvider(kp)(opts)
	WithLeeway(DefaultLeeway)(opts)
	return opts, nil
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
	parser          *jwt.Parser
	keyfuncProvider keyfunc.Provider
	issuer          string
}

// NewVerifier creates a new Verifier for the specified issuer.
func NewVerifier(issuer string, options ...Option) (*Verifier, error) {
	opts, err := defaultOptions(issuer)
	if err != nil {
		return nil, fmt.Errorf("creating default options: %w", err)
	}
	for _, option := range options {
		option(opts)
	}

	// Configure JWT parser
	parser := jwt.NewParser(
		jwt.WithLeeway(opts.leeway),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)

	return &Verifier{issuer: issuer, keyfuncProvider: opts.keyfuncProvider, parser: parser}, nil
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

	token, err := v.parser.Parse(tokenString, keyfunc)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	return token, err
}

// validateCommonClaims validates claims that aren't validated natively by jwt.Parser
func (v *Verifier) validateCommonClaims(ctx context.Context, jwt *jwt.Token) error {
	claims := jwt.Claims

	jwtIat, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("verifying id token issued time: %w", err)
	}

	if jwtIat == nil {
		return fmt.Errorf("verifying token issued time: no issued time found")
	}

	return nil
}
