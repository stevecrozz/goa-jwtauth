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
		middleware := jwt.New(scheme, "This is my HMAC key)

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

		middleware := jwt.NewWithKeystore(scheme, store)

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

*/
package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

type (
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
)

// New returns a middleware that is configured to trust a single key.
func New(scheme *goa.JWTSecurity, key Key) goa.Middleware {
	store := &SingleKeystore{Key: key}
	return NewWithKeystore(scheme, store)
}

// New returns a middleware that uses store as its keystore.
func NewWithKeystore(scheme *goa.JWTSecurity, store Keystore) goa.Middleware {
	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			token, err := parseToken(scheme, store, req)
			if err != nil {
				return err
			}

			ctx = WithJWT(ctx, token)

			return nextHandler(ctx, rw, req)
		}
	}
}

func parseToken(scheme *goa.JWTSecurity, store Keystore, req *http.Request) (*jwt.Token, error) {
	if scheme.In != goa.LocHeader {
		return nil, fmt.Errorf("Unsupported goa.JWTSecurity.In '%s' (expected %s)", scheme.In, goa.LocHeader)
	}

	token := extractToken(req.Header.Get(scheme.Name))
	if token == "" {
		return nil, nil
	}

	return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		iss, err := identifyIssuer(token)
		if err != nil {
			return nil, err
		}
		key := store.Get(iss)
		if key == nil {
			return nil, fmt.Errorf("Untrusted issuer '%s'", iss)
		}
		return key, nil
	})
}

func extractToken(header string) string {
	bits := strings.SplitN(header, " ", 2)
	if len(bits) == 1 {
		return bits[0]
	}
	return bits[1]
}

func identifyIssuer(token *jwt.Token) (string, error) {
	switch claims := token.Claims.(type) {
	case jwt.MapClaims:
		iss, ok := claims["iss"].(string)
		if ok {
			return iss, nil
		}
		return "", fmt.Errorf("Unsupported issuer type %T; expected string", claims["iss"])
	case *jwt.StandardClaims:
		return claims.Issuer, nil
	default:
		return "", fmt.Errorf("Unsupported JWT claims type %T", claims)
	}
}
