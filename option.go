package jwtauth

import "github.com/goadesign/goa"

type (
	// mwopts is a state accumulator for Option.
	mwopts struct {
		Scheme         *goa.JWTSecurity
		Keystore       Keystore
		Authentication AuthenticationFunc
		Authorization  AuthorizationFunc
	}

	// Option is a function that applies options. Its signature contains unexported
	// types and is not meant to be used directly. Instead, call the WithXxx()
	// family of factory functions to instantiate suitable options.
	Option func(*mwopts)
)

// WithAuthentication overrides the default authorization behavior for a
// jwtauth middleware.
//
// The default behavior is to extract the "iss" (Issuer) claim from the
// JWT and put it in the context so that it can be retrieved using
// ContextPrincipal().
func WithAuthentication(fn AuthenticationFunc) Option {
	return func(o *mwopts) {
		o.Authentication = fn
	}
}

// WithAuthorization overrides the default authorization behavior for a jwtauth
// middleware.
//
// The default behavior is to compare a private claim named "scopes" from
// the token with each of the goa.ContextRequiredScopes(), ensuring that the
// token contains every required scope.
func WithAuthorization(fn AuthorizationFunc) Option {
	return func(o *mwopts) {
		o.Authorization = fn
	}
}
