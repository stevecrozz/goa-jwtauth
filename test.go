package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

const testKey = "https://github.com/xeger/goa-middleware-jwt#test"

// TestMiddleware returns a middleware that uses a static HMAC key and is
// suitable for unit tests.
func TestMiddleware(scheme *goa.JWTSecurity) goa.Middleware {
	return Authentication(scheme, []byte(testKey))
}

// TestToken creates a JWT with the specified claims and signs it using
// the same static HMAC key used by TestMiddleware().
//
// This method assumes that odd-numbered keyvals are always strings (claim names)
// and panics otherwise.
//
// Example of token identifying Bob, issued by Alice, and good for one hour:
//      tok := jwt.TestToken("iss", "alice", "sub", "bob", "exp", time.Now().Add(time.Hour))
func TestToken(keyvals ...interface{}) string {
	claims := jwt.MapClaims{}

	var k string
	for i, v := range keyvals {
		if i%2 == 0 {
			k = v.(string)
		} else {
			claims[k] = v
		}
	}

	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "test"
	}

	jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	str, err := jwt.SignedString([]byte(testKey))
	if err != nil {
		panic(err)
	}
	return str
}
