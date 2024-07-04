# okta-jwt-verifier

[![Test](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml)
[![GoDoc](https://godoc.org/github.com/sovietaced/okta-jwt-verifier?status.png)](http://godoc.org/github.com/sovietaced/okta-jwt-verifier)
[![Go Report](https://goreportcard.com/badge/github.com/sovietaced/okta-jwt-verifier)](https://goreportcard.com/report/github.com/sovietaced/okta-jwt-verifier)

Alternative implementation to the official [okta-jwt-verifier](https://github.com/okta/okta-jwt-verifier-golang) that 
includes support for telemetry (ie. OpenTelemetry), minimizing verification latency, and testability.

## Examples

### Token Validation

```go 
package main

import (
    "context"
    verifier "github.com/sovietaced/okta-jwt-verifier"
)

func main() {
    ctx := context.Background()
    issuer := "https://test.okta.com"
    v, err := verifier.NewVerifier(issuer)

    idToken := "..."
    token, err := v.VerifyIdToken(ctx, idToken)

    accessToken := "..."
    token, err = v.VerifyAccessToken(ctx, accessToken)
}
```

### Background Fetching Optimization
By default, the okta JWT verifier will lazily fetch OIDC metadata and JSON Web Key sets. When the first call to verify a 
token is made a couple of HTTP requests will be made inline and block your call to verify the token. You can configure 
the verifier to fetch OIDC metadata and JSON Web Key sets asynchronously in the background to optimize token
verification duration. 

```go 
package main

import (
    "context"
    kf "github.com/sovietaced/okta-jwt-verifier/keyfunc/okta"
    md "github.com/sovietaced/okta-jwt-verifier/metadata/okta"
    verifier "github.com/sovietaced/okta-jwt-verifier"
)

func main() {
    ctx := context.Background()
    issuer := "https://test.okta.com"

    mpProvider, err := md.NewMetadataProvider(issuer, md.WithFetchStrategy(md.Background))
    kfProvider, err := kf.NewKeyfuncProvider(mpProvider, kf.WithFetchStrategy(kf.Background))
    v, err := verifier.NewVerifier(issuer, verifier.WithKeyfuncProvider(kfProvider))

    idToken := "..."
    token, err := v.VerifyIdToken(ctx, idToken)

    accessToken := "..."
    token, err = v.VerifyAccessToken(ctx, accessToken)
}
```



