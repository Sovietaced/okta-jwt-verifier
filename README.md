# okta-jwt-verifier

[![Test](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/sovietaced/okta-jwt-verifier/actions/workflows/ci.yml)
[![GoDoc](https://godoc.org/github.com/sovietaced/okta-jwt-verifier?status.png)](http://godoc.org/github.com/sovietaced/okta-jwt-verifier)
[![Go Report](https://goreportcard.com/badge/github.com/sovietaced/okta-jwt-verifier)](https://goreportcard.com/report/github.com/sovietaced/okta-jwt-verifier)

Alternative implementation to the official [okta-jwt-verifier](https://github.com/okta/okta-jwt-verifier-golang) that 
includes support for telemetry (ie. OpenTelemetry), minimizing operational latency, and testability.

## Examples

### ID Token Validation

```go
import (
    "context"
    verifier "github.com/sovietaced/okta-jwt-verifier"
)

func main() {
    ctx := context.Background()
    issuer := "https://test.okta.com"
    clientId := "test"
    v := verifier.NewVerifier(issuer, clientId)

    idToken := "..."
    token, err := v.VerifyIdToken(ctx, idToken)
}

```

