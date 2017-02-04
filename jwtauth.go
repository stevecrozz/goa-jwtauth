/*
Package jwtauth provides a middleware for the Goa framework that parses and
validates JSON Web Tokens (JWTs) that appear in requests, then adds them
to the request context. It supports any JWT algorithm that uses RSA, ECDSA
or HMAC.

When you setup your goa.Service, install the jwtauth middleware:

		scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
		middleware := jwtauth.New(scheme, "This is my HMAC key")

In this example, jwtauth uses a single, static HMAC key and relies
on the default authentication and authorization behavior. When someone makes
a request containing a JWT, jwauth verifies that the token contains all of
the scopes that are required by your action, as determined by goa.ContextRequiredScopes().
If anything is missing, jwtauth returns 4xx or 5xx error with a detailed message.

Custom Auth Behaviors
---------------------

To change how jwtauth performs auth, write your own function that matches the
signature of jwt.Authentication() or jwt.Authorization(), then pass it to the
constructor using jwtauth's options DSL:

		middleware := jwtauth.New(scheme, "This is my HMAC key",
			jwtauth.WithAuthentication(myAuthnFunc),
			jwtauth.WithAuthorization(myAuthzFunc)
		)

Authentication is largely boring and there is probably no reason to customize.
The details of authorization can vary heavily between use cases; many non-toy
services will need to customize the authorization behavior.

When overriding either behavior, you can always delegate some work to the
default behavior. To check with a central authorization server to ensure that
the user is alive and well:

		func myAuthzFunc(ctx context.Context, claims jwtauth.Claims) error {
			tokenAuth := jwtauth.Authorize(ctx, claims)
			http.Get(fmt.Sprintf("http://auth-server?%s", claims.Subject()))
		}

Token Management
----------------

If you need to create tokens, jwtauth contains a simplistic helper that helps
to shadow the dependency on dgrijalva/jwt:

		claims := jwtauth.NewClaims()
		token, err := NewToken("my HMAC key", claims)
		fmt.Println("the magic token is", token)

Error handling
--------------

Common errors are returned as instances of a goa error class, which have
the effect of responding with a specific HTTP status:

ErrUnsupported (500): the token or configuration uses an unsupported feature.

ErrInvalidToken (401): the token is malformed or its signature is bad.

ErrAuthenticationFailed (403): the token is well-formed but the issuer is not
trusted, it has expired, or is not yet valid.

ErrAuthorizationFailed (403): the token is well-formed and valid, but the
authentication principal did not satisfy all of the scopes required to call
the requested goa action.

Multiple issuers and keys
--------------------------

For real-world applications, it is advisable to register several trusted keys
so you can perform key rotation on the fly and compartmentalize trust. If you
initialize the middleware with a NamedKeystore, it uses the value of the
JWT "iss" (Issuer) claim to select a verification key for each token.

		import jwtgo "github.com/dgrijalva/jwt-go"
		us := jwtgo.ParseRSAPublicFromPEM(ioutil.ReadFile("us.pem))
		eu := jwtgo.ParseRSAPublicKeyFromPEM(ioutil.ReadFile("eu.pem))

		scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
		store := jwt.NamedKeystore{}
		store.Trust("us.acme.com", []byte("secret HMAC key for US servers"))
		store.Trust("eu.acme.com", []byte("secret HMAC key for EU servers"))

		middleware := jwt.New(scheme, store)

Using a NamedKeystore, you can grant or revoke trust at any time, even while
the application is running, and your changes will take effect on the next
request.

JWT Location and Format
-----------------------

Package jwtauth supports security schemes that use goa.LocHeader; JWTs in
the query string, or in other locations, are not supported.

Although jwtauth uses the header name specified by the goa.JWTSecurity definition
that is used to initialize it, some assumptions are made about the format of
the header value. It must contain a base64-encoded JWT, which may be prefixed
by a single-word qualifier. Assuming the security scheme uses the Authorization
header, any of the following would be acceptable:

		Authorization: <base64_token>
		Authorization: Bearer <base64_token>
		Authorization: JWT <base64_token>
		Authorization: AnyOtherWordHere <base64_token>

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
	// Key is any cryptographic key that is supported for token creation or
	// verification. This includes the following types:
	//   - []byte for HMAC tokens
	//   - *ecdsa.PublicKey for ECDSA tokens
	//   - *rsa.PublicKey for RSA tokens
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

	// AuthenticationFunc is an optional callback that allows customization
	// of the way the middleware identifies the authentication principal
	// for a given request.
	AuthenticationFunc func(context.Context, Claims) (string, error)

	// AuthorizationFunc is an optional callback that allows customization
	// of the way the middleware authorizes each request.
	AuthorizationFunc func(context.Context, Claims) error

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
