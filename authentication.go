package jwtauth

import "golang.org/x/net/context"

// Authentication is the default authentication method. It extracts the "iss"
// (Issuer) claim from the JWT and stores it in request context, where it can
// be retrieved by authorization middleware or business logic by calling
// ContextPrincipal().
func Authentication(ctx context.Context, claims Claims) (string, error) {
	var princ string
	if sub, ok := claims["sub"].(string); ok {
		princ = sub
	}
	return princ, nil
}
