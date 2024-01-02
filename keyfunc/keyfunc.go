package keyfunc

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
)

// Provider is a pluggable provider of JWT verifying key functions.
type Provider interface {
	// GetKeyfunc gets the JWT verifying key function for an issuer.
	GetKeyfunc(ctx context.Context) (jwt.Keyfunc, error)
}
