package jwtauth

import (
	"fmt"

	"golang.org/x/net/context"
)

// SimpleAdapter implements a simplistic authorization scheme that relies only
// on a list of access scopes stored in the JWT itself, checking the token's
// scopes against goa's list of required scopes whenever a request is made.
//
//
// The "sub" claim is assumed to contain the authentication principal that
// holds the scopes.
//
// The JWT specification deliberately does not define a claim that represents
// scope, so there is no "standard" name for ScopesClaim. If you want your JWT
// claims to be meaningful to other organizations, you should use a Collision-
// Resistant Name as defined in RFC7519 Section 2, such as your company's
// http:// URL. If you do not need to interoperate, then you can use a private
// claim name such as "scopes."
type SimpleAdapter struct {
	ScopesClaim string
}

// GetPrincipal extracts the "sub" claim from a set of JWT claims, transforms
// it into a string, and returns the string.
//
// If the claims do not contain a subject, GetPrincipal returns the empty
// string.
func (sa SimpleAdapter) GetPrincipal(ctx context.Context, claims Claims) (string, error) {
	switch sub := claims["sub"].(type) {
	case string:
		return sub, nil
	case fmt.Stringer:
		return sub.String(), nil
	default:
		if sub == nil {
			return "", nil
		}
		return fmt.Sprintf("%v", sub), nil
	}
}

// GetScopes extracts the scopes from a set of JWT claims, transforms them
// into a slice of strings, and returns the slice.
//
// If the claims contain no scope, GetScopes returns nil.
func (sa SimpleAdapter) GetScopes(ctx context.Context, claims Claims) ([]string, error) {
	s := claims[sa.ScopesClaim]
	if s == nil {
		return nil, nil
	}

	is, ok := s.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Expected %s claim to be a []interface{}; got %T", sa.ScopesClaim, s)
	}

	scopes := make([]string, len(is))
	for i, s_i := range is {
		switch ts_I := s_i.(type) {
		case string:
			scopes[i] = ts_I
		case fmt.Stringer:
			scopes[i] = ts_I.String()
		default:
			scopes[i] = fmt.Sprintf("%v", ts_I)
		}
	}

	return scopes, nil
}

// Authorize checks that every required scope is present in the token's list
// of scopes. If all scopes are satisfied, or if no scopes are required,
// Authorize returns nil.
func (sa SimpleAdapter) Authorize(ctx context.Context, principal interface{}, tokenScopes, requiredScopes []string) error {
	for _, rs := range requiredScopes {
		found := false
		for _, ts := range tokenScopes {
			if rs == ts {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Authorization failed; token does not contain required scope %s", rs)
		}
	}
	return nil
}
