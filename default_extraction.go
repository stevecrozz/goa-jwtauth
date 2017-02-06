package jwtauth

import (
	"net/http"
	"strings"

	"github.com/goadesign/goa"
)

// DefaultExtraction is the default token-extraction method. It finds the header
// named in the security scheme, discards an optional one-word prefix such as
// "Bearer" or "JWT", and returns the remainder of the header value.
//
// DefaultExtraction is compatible with OAuth2 bearer-token and other schemes
// that use the Authorization header to transmit a JWT.
func DefaultExtraction(scheme *goa.JWTSecurity, req *http.Request) (string, error) {
	var header string
	switch scheme.In {
	case goa.LocHeader:
		header = req.Header.Get(scheme.Name)
	default:
		return "", ErrUnsupported("unexpected goa.JWTSecurity.In", "expected", goa.LocHeader, "got", scheme.In)
	}

	bits := strings.SplitN(header, " ", 2)
	if len(bits) == 1 {
		return bits[0], nil
	}
	return bits[1], nil
}
