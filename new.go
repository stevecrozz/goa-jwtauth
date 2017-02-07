package jwtauth

import (
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	"golang.org/x/net/context"
)

// New creates a jwtauth middleware with the specified security scheme,
// keystore, and options.
func New(scheme *goa.JWTSecurity, store Keystore, options ...Option) goa.Middleware {
	oo := &mwopts{}
	oo.Scheme = scheme
	oo.Keystore = store
	oo.Extraction = DefaultExtraction
	oo.Authorization = DefaultAuthorization

	for _, o := range options {
		o(oo)
	}

	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			token, err := parseToken(oo.Scheme, oo.Keystore, oo.Extraction, req)
			if err != nil {
				return err
			}

			claims := Claims{}
			if token != nil {
				switch tc := token.Claims.(type) {
				case *jwt.StandardClaims:
					claims["aud"] = tc.Audience
					claims["id"] = tc.Id
					claims["iss"] = tc.Issuer
					claims["sub"] = tc.Subject
					claims["iat"] = tc.IssuedAt
					claims["nbf"] = tc.NotBefore
					claims["exp"] = tc.ExpiresAt
				case jwt.MapClaims:
					claims = Claims(tc)
				default:
					typ := fmt.Sprintf("%T", tc)
					return ErrInvalidToken("unsupported jwt.Claims", "type", typ)
				}
			}

			ctx = WithClaims(ctx, claims)

			if oo.Authorization != nil {
				err = oo.Authorization(ctx, claims)
			}

			if err == nil {
				return nextHandler(ctx, rw, req)
			}
			return err
		}
	}
}

// NewToken creates a JWT with the specified claims and signs it using
// the specified issuer key.
//
// This method assumes that odd-numbered keyvals are always strings (claim names)
// and panics otherwise.
//
// Example token identifying Bob, issued by Alice, and good for one hour:
//      exp := time.Now().Add(time.Hour)
//      claims := jwt.NewClaims("iss", "alice", "sub", "bob", "exp", exp)
//      tok := jwt.NewToken(alicesKey, claims)
//
// Example token that contains authorization scopes, which the default
// authorization function will test against goa's RequiredScopes:
//      scopes = []string{"read","write"}
//      claims := jwt.NewClaims("iss", "alice", "exp", exp, jwtauth.ScopesClaim, scopes)
//
// In order for recipients to verify the example tokens above, their keystore
// must associate the "alice" issuer with alicesKey -- which can be either a
// []byte (for HMAC tokens) or a crypto.PrivateKey (for public-key tokens).
//
// There is no standard claim name for authorization scopes, so jwtauth uses
// the least-surprising name, "scopes." See Authorization() to learn more
// about claims and scopes.
func NewToken(key interface{}, claims Claims) (string, error) {
	method := key2method(key)
	if method == nil {
		return "", fmt.Errorf("Unsupported key type %T", key)
	}
	jwt := jwt.NewWithClaims(method, jwt.MapClaims(claims))
	return jwt.SignedString(key)
}

// NewClaims builds a map of claims using alternate keys and values from the
// variadic parameters. It is sugar designed to make new-token creation code
// more readable. Example:
//
//     claims := jwtauth.NewClaims("iss", "alice", "sub", "bob", "scopes", []string{"read", "write"})
//
// If any odd-numbered key is not a string, this function will panic!
func NewClaims(keyvals ...interface{}) Claims {
	claims := Claims{}

	var k string
	for i, v := range keyvals {
		if i%2 == 0 {
			k = v.(string)
		} else {
			claims[k] = v
		}
	}

	return claims
}
