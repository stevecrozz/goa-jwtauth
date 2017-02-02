/*
Package jwt provides a middleware for the Goa framework that parses and
validates JSON Web Tokens (JWTs) that appear in requests, then adds them
to the request context. It supports any JWT algorithm that uses RSA, ECDSA
or HMAC.

Note that jwt does not actually PERFORM authentication or authorization; it
merely validates the token's trustworthiness so another middleware, or the
application itself, can make security decisions based on the token's claims.

As a trivial example, to setup JWT security with a static HMAC key using an
OAuth-compatible header transport:

		scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
		middleware := jwt.Authentication(scheme, "This is my HMAC key)

Issuers and keys
----------------

For real-world applications, it is advisable to register several trusted keys
so you can perform key rotation on the fly and compartmentalize trust. If you
initialize the middleware with a NamedKeystore, it uses the value of the
JWT "iss" (Issuer) claim to identify the verifying key for a particular token.
As an example:

		import jwtgo "github.com/dgrijalva/jwt-go"
		us := jwtgo.ParseRSAPublicFromPEM(ioutil.ReadFile("us.pem))
		eu := jwtgo.ParseRSAPublicKeyFromPEM(ioutil.ReadFile("eu.pem))

		scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
		store := jwt.NamedKeystore{}
		store.Trust("us.acme.com", "secret HMAC key for US servers")
		store.Trust("eu.acme.com", "secret HMAC key for EU servers")

		middleware := jwt.AuthenticationWithKeystore(scheme, store)

Using a NamedKeystore, you can grant or revoke trust at any time, even while
the application is running, and your changes will take effect on the next
request.

JWT Location and Format
-----------------------

Package jwt supports security schemes that use goa.LocHeader; JWTs in
the query string, or in other locations, are not supported.

Although jwt uses the header name specified by the goa.JWTSecurity definition
that is used to initialize it, some assumptions are made about the format of
the header value. It must contain a base64-encoded JWT, which may be prefixed
by a single-word qualifier. Assuming the security scheme uses the Authorization
header, any of the following would be acceptable:

		Authorization: <base64_token>
		Authorization: Bearer <base64_token>
		Authorization: JWT <base64_token>
		Authorization: AnyOtherWordHere <base64_token>

Error handling
--------------

If the security scheme is misconfigured (e.g. unsupported location) then
jwt fails all requests.

If a request is missing the auth header, jwt passes the request but fails to
populate the context with a JWT, i.e. the request is unauthenticated.

If the header contains a well-formed token that is expired, not-yet-trustable,
or has some other trust issue, jwt fails the request.

If the header contains a malformed token, jwt fails the request.

Testing
-------

Call TestMiddleware() to create a middleware initialized to trust a static key,
e.g. for unit tests.

Call TestToken() to create a valid token signed by the same key.

NEVER USE THESE FUNCTIONS in production; they are intended only for testing!

*/
package jwtauth

import "golang.org/x/net/context"

type (
	// Claims is a collection of claims extracted from a JWT.
	Claims map[string]interface{}

	// Key represents a cryptographic key using an unspecified algorithm, which
	// can be used to verify the signatures of JSON Web Tokens.
	//
	// The underlying type may be a []byte (for HMAC-based "HS" tokens), or an
	// algorithm-specific key type such as *rsa.PublicKey (for "RS" tokens) or
	// *ecdsa.PublicKey (for "ES" tokens).
	Key interface{}

	// Keystore is a directory of trusted JWT issuers and their keys.
	//
	// When the middleware receives a request containing a JWT, it extracts the
	// "iss" (Issuer) claim from the JWT body and gets a correspondingly-named
	// key from the keystore, which it uses to verify the JWT's integrity.
	Keystore interface {
		// Trust grants trust in an issuer.
		Trust(issuer string, key Key) error
		// RevokeTrust revokes trust in an issuer.
		RevokeTrust(issuer string)
		// Get returns the key associated with the named issuer.
		Get(issuer string) Key
	}

	// Adapter allows applications to customize the authorization scheme
	// in order to account for different usages of JWT claims and different ways
	// of interpreting scope.
	Adapter interface {
		// GetPrincipal returns the authentication principal specified in the
		// claims, or the empty string if no suitable claim is present.
		GetPrincipal(context.Context, Claims) (string, error)
		// GetScopes returns a list of scopes specified in the claims, or nil if
		// no scopes are present.
		GetScopes(context.Context, Claims) ([]string, error)
		// Authorize returns nil if the principal is authorized to perform a
		// request, or an error the principal is forbidden.
		Authorize(ctx context.Context, principal interface{}, tokenScopes, requiredScopes []string) error
	}
)
