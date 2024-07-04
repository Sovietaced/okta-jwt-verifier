# okta-jwt-verifier

[![Test](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml)
[![GoDoc](https://godoc.org/github.com/sovietaced/okta-jwt-verifier?status.png)](http://godoc.org/github.com/sovietaced/okta-jwt-verifier)
[![Go Report](https://goreportcard.com/badge/github.com/sovietaced/okta-jwt-verifier)](https://goreportcard.com/report/github.com/sovietaced/okta-jwt-verifier)

Alternative implementation to the official [okta-jwt-verifier](https://github.com/okta/okta-jwt-verifier-golang) that 
includes support for telemetry (ie. OpenTelemetry), minimizing verification latency, and testability.

## Examples

### Access Token Validation

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

