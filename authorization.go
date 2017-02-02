package jwtauth

import (
	"fmt"
	"net/http"

	"golang.org/x/net/context"

	"github.com/goadesign/goa"

	jwt "github.com/dgrijalva/jwt-go"
)

// Authorization returns a middleware that authorizes requests
func Authorization(scheme *goa.JWTSecurity, scopesClaimName string) goa.Middleware {
	return AuthorizationWithAdapter(scheme, SimpleAdapter{scopesClaimName})
}

// AuthorizationWithAdapter returns a middleware that authorizes requests using
// the specified Adapter.
func AuthorizationWithAdapter(scheme *goa.JWTSecurity, adapter Adapter) goa.Middleware {
	return func(nextHandler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			log := goa.ContextLogger(ctx)
			token := ContextJWT(ctx)
			requiredScopes := goa.ContextRequiredScopes(ctx)

			if token == nil {
				if len(requiredScopes) == 0 {
					return nextHandler(ctx, rw, req)
				} else {
					// TODO replace with 403 Forbidden
					return fmt.Errorf("GO AWAY")
				}
			}

			var claims Claims
			switch tc := token.Claims.(type) {
			case jwt.MapClaims:
				claims = Claims(tc)
			default:
				return fmt.Errorf("Unsupported jwt Claims type %T", tc)
			}
			principal, err := adapter.GetPrincipal(ctx, claims)
			if err != nil {
				return err
			}
			tokenScopes, err := adapter.GetScopes(ctx, claims)
			if err != nil {
				return err
			}
			err = adapter.Authorize(ctx, principal, tokenScopes, requiredScopes)
			if err == nil {
				return nextHandler(ctx, rw, req)
			}

			if log != nil {
				log.Error("jwt.Authorization", "sub", principal, "scopes", tokenScopes, "req", requiredScopes, "err", err)
			}
			return err
		}
	}
}
