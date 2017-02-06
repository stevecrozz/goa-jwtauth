package jwtauth

import "golang.org/x/net/context"

type contextKey int

const (
	claimsKey contextKey = iota + 1
	principalKey
)

// WithClaims creates a child context containing the given claims.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}

// ContextClaims retrieves the JWT claims associated with the request.
func ContextClaims(ctx context.Context) Claims {
	claims, _ := ctx.Value(claimsKey).(Claims)
	return claims
}
