package jwt

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

// Authentication returns a middleware that is configured to trust a single key.
func Authentication(scheme *goa.JWTSecurity, key Key) goa.Middleware {
	store := &SimpleKeystore{Key: key}
	return AuthenticationWithKeystore(scheme, store)
}

// AuthenticationWithKeystore returns a middleware that uses store as its keystore.
func AuthenticationWithKeystore(scheme *goa.JWTSecurity, store Keystore) goa.Middleware {
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
