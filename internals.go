package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

// parseToken does the gruntwork of extracting A JWT from a request.
func parseToken(scheme *goa.JWTSecurity, store Keystore, exfn ExtractionFunc, req *http.Request) (*jwt.Token, error) {
	tok, err1 := exfn(scheme, req)
	if err1 != nil {
		return nil, err1
	}

	var alg string
	var key interface{}
	parsed, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		alg, _ = token.Header["alg"].(string)
		iss, err := identifyIssuer(token)
		if err != nil {
			return nil, err
		}
		key = store.Get(iss)
		if key == nil {
			return nil, ErrInvalidToken("untrusted", "issuer", iss)
		}
		return key, nil
	})

	// help clients with mystery errors caused by fast-and-loose key
	// typing in crypto and dgrijalva/jwt-go
	if err != nil && strings.HasPrefix(err.Error(), "key is of invalid type") {
		err = fmt.Errorf("%s (%T for algorithm %s)", err.Error(), key, alg)
		panic(err)
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		err = ve.Inner
	}
	if err != nil {
		err = ErrInvalidToken(err.Error(), "token", tok)
	}

	return parsed, err
}

// identifyIssuer inspects a JWT's claims to determine its issuer.
func identifyIssuer(token *jwt.Token) (string, error) {
	if token == nil || token.Claims == nil {
		return "", nil
	}

	switch claims := token.Claims.(type) {
	case *jwt.StandardClaims:
		return claims.Issuer, nil
	case jwt.MapClaims:
		var issuer string
		if claims != nil {
			iss := claims["iss"]
			if iss == nil {
				return "", nil
			}
			switch it := iss.(type) {
			case string:
				issuer = it
			case fmt.Stringer:
				issuer = it.String()
			}
		}
		return issuer, nil
	default:
		typ := fmt.Sprintf("%T", claims)
		return "", ErrUnsupported("unsupported jwt.Claims", "type", typ)
	}
}

// key2method determines a JWT SigningMethod that is suitable for the given key.
func key2method(key interface{}) jwt.SigningMethod {
	switch key.(type) {
	case []byte, string:
		return jwt.SigningMethodHS256
	case rsa.PrivateKey, *rsa.PrivateKey, rsa.PublicKey, *rsa.PublicKey:
		return jwt.SigningMethodRS256
	case ecdsa.PrivateKey, *ecdsa.PrivateKey, ecdsa.PublicKey, *ecdsa.PublicKey:
		return jwt.SigningMethodES256
	default:
		return nil
	}
}
