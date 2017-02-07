package jwtauth

import "github.com/goadesign/goa"

const TestKey = "https://github.com/rightscale/goa-jwtauth#test"

// TestMiddleware returns a middleware that uses a static HMAC key and is
// suitable for unit tests.
func TestMiddleware(scheme *goa.JWTSecurity) goa.Middleware {
	return New(scheme, &SimpleKeystore{Key: []byte(TestKey)})
}

// TestToken creates a JWT with the specified claims and signs it using
// the same static HMAC key used by TestMiddleware().
func TestToken(keyvals ...interface{}) string {
	key := []byte(TestKey)
	token, err := NewToken(key, NewClaims(keyvals...))
	if err != nil {
		panic(err)
	}
	return token
}
