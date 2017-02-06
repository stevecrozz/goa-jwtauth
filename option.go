package jwtauth

import "github.com/goadesign/goa"

type (
	// mwopts is a state accumulator for Option.
	mwopts struct {
		Scheme        *goa.JWTSecurity
		Keystore      Keystore
		Extraction    ExtractionFunc
		Authorization AuthorizationFunc
	}

	// Option is a function that applies options. Its signature contains unexported
	// types and is not meant to be used directly. Instead, call the WithXxx()
	// family of factory functions to instantiate suitable options.
	Option func(*mwopts)
)

// Extraction overrides the default token-extraction behavior for a jwtauth
// middleware.
//
// The default behavior is to call the DefaultAuthorization() function.
func Extraction(fn ExtractionFunc) Option {
	return func(o *mwopts) {
		o.Extraction = fn
	}
}

// Authorization overrides the default authorization behavior for a jwtauth
// middleware.
//
// The default behavior is to call the DefaultAuthorization() function.
func Authorization(fn AuthorizationFunc) Option {
	return func(o *mwopts) {
		o.Authorization = fn
	}
}
