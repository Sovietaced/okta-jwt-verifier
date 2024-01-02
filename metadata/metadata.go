package metadata

import (
	"context"
)

// Provider is a pluggable provider of OIDC metadata.
type Provider interface {
	GetMetadata(ctx context.Context) (Metadata, error)
}

// Metadata represents the OIDC metadata response from Okta. We only care about the JWKS URI.
// See: https://developer.okta.com/docs/reference/api/oidc/#well-known-openid-configuration
type Metadata struct {
	JwksUri string `json:"jwks_uri"`
}
