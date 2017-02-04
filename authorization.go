package jwtauth

import (
	"fmt"

	"github.com/goadesign/goa"
	"golang.org/x/net/context"
)

// ScopesClaim is a Private Claim Name, as stipulated in RFC7519 Section 4.3,
// that jwtauth uses to store scope information in tokens. If you need to
// interoperate with third parties w/r/t to token scope, it may be advisable
// to change this to a Collision-Resistant Claim Name instead.
var ScopesClaim = "scopes"

// Authorization is the default authorization method. It compares the context's
// required scopes against a list of scopes that are claimed in the JWT. If
// the claimed scopes satisfy all required scopes, Authorization passes the
// request; otherwise, it responds with ErrAuthorizationFailed.
func Authorization(ctx context.Context, claims Claims) error {
	reqd := goa.ContextRequiredScopes(ctx)

	held := ParseScopes(claims[ScopesClaim])

	for _, r := range reqd {
		found := false
		for _, h := range held {
			found = found || (h == r)
			if found {
				break
			}
		}
		if !found {
			return ErrAuthorizationFailed("missing scopes", "required", reqd)
		}
	}
	return nil
}

// ParseScopes tries to interpret an arbitrary JWT claim as a list of scopes.
// It accepts a single value or array of values, transforms everything to
// a string, and returns an array of strings.
func ParseScopes(claim interface{}) (scopes []string) {
	slice, _ := claim.([]interface{})
	if slice == nil && claim != nil {
		slice = []interface{}{claim}
	}

	if slice != nil {
		for _, e := range slice {
			switch et := e.(type) {
			case string:
				scopes = append(scopes, et)
			default:
				scopes = append(scopes, fmt.Sprintf("%v", et))
			}
		}
	}
	return
}
