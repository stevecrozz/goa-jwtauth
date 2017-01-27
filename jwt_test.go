package jwt_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"golang.org/x/net/context"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwt "github.com/xeger/goa-middleware-jwt"
)

var _ = Describe("JWT middleware", func() {
	Context("error handling", func() {
		var resp *httptest.ResponseRecorder
		var req *http.Request

		var handler goa.Handler

		BeforeEach(func() {
			resp = httptest.NewRecorder()
			req, _ = http.NewRequest("GET", "http://example.com/", nil)
			handler = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
				return nil
			}
		})

		It("rejects unknown issuers", func() {
			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			store := &jwt.NamedKeystore{}
			middleware := jwt.NewWithKeystore(scheme, store)

			setBearerHeader(req, makeToken("suspicious-issuer", hmacKey1))

			result := middleware(handler)(context.Background(), resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("fails when JWTSecurity.Location is unsupported", func() {
			scheme := &goa.JWTSecurity{In: goa.LocQuery, Name: "jwt"}
			store := &jwt.NamedKeystore{}
			middleware := jwt.NewWithKeystore(scheme, store)

			result := middleware(handler)(context.Background(), resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("rejects malformed issuers", func() {
			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			middleware := jwt.New(scheme, hmacKey1)
			claims := jwtpkg.MapClaims{}
			claims["iss"] = 7
			token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, &claims)
			s, err := token.SignedString(hmacKey1)
			if err != nil {
				panic(err)
			}
			setBearerHeader(req, s)

			result := middleware(handler)(context.Background(), resp, req)

			Ω(result).Should(HaveOccurred())
		})
	})

	Context("given HMAC keys", func() {
		testShared(hmacKey1, hmacKey2)
	})

	Context("given RSA keys", func() {
		testShared(rsaKey1, rsaKey2)
	})

	Context("given ECDSA keys", func() {
		testShared(ecKey1, ecKey2)
	})
})

// TestShared defines test cases that are repeated for every supported key
// type.
func testShared(trusted, untrusted jwt.Key) {
	scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}

	var resp *httptest.ResponseRecorder
	var req *http.Request

	var handler goa.Handler
	var middleware goa.Middleware
	var token *jwtpkg.Token

	BeforeEach(func() {
		resp = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "http://example.com/", nil)
		handler = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			token = jwt.ContextJWT(ctx)
			return nil
		}

		var key jwt.Key
		switch tk := trusted.(type) {
		case []byte:
			key = trusted
		case *rsa.PrivateKey:
			key = jwt.Key(&tk.PublicKey)
		case *ecdsa.PrivateKey:
			key = jwt.Key(&tk.PublicKey)
		default:
			panic("Unsupported key type for tests")
		}

		middleware = jwt.New(scheme, key)

		token = nil
	})

	It("accepts requests that lack tokens", func() {
		result := middleware(handler)(context.Background(), resp, req)
		Ω(result).ShouldNot(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("accepts valid tokens", func() {
		setBearerHeader(req, makeToken("_", trusted))

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).ShouldNot(HaveOccurred())
		Ω(token).ShouldNot(BeNil())
	})

	It("rejects modified tokens", func() {
		bad := modifyToken(makeToken("_", trusted))
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects untrusted tokens", func() {
		setBearerHeader(req, makeToken("_", untrusted))

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects expired tokens", func() {
		iat := time.Now().Add(-time.Hour)
		exp := iat.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", trusted, iat, iat, exp)
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects not-yet-valid tokens", func() {
		iat := time.Now()
		nbf := iat.Add(time.Minute)
		exp := nbf.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", trusted, iat, nbf, exp)
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})
}

func makeToken(issuer string, key jwt.Key) string {
	now := time.Now()
	return makeTokenWithTimestamps(issuer, key, now, now, now.Add(time.Minute))
}

func makeTokenWithTimestamps(issuer string, key jwt.Key, iat, nbf, exp time.Time) string {
	claims := jwtpkg.StandardClaims{}
	claims.Issuer = issuer
	claims.IssuedAt = iat.Unix()
	claims.NotBefore = nbf.Unix()
	claims.ExpiresAt = exp.Unix()

	var token *jwtpkg.Token
	switch key.(type) {
	case []byte:
		token = jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, &claims)
	case *rsa.PrivateKey:
		token = jwtpkg.NewWithClaims(jwtpkg.SigningMethodRS256, &claims)
	case *ecdsa.PrivateKey:
		token = jwtpkg.NewWithClaims(jwtpkg.SigningMethodES256, &claims)
	default:
		panic("Unsupported key type for tests")
	}

	s, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	return s
}

func modifyToken(token string) string {
	// modify a single byte
	return strings.Replace(token, token[25:26], string(byte(token[25])+1), 1)
}

func setBearerHeader(req *http.Request, token string) {
	header := fmt.Sprintf("Bearer %s", token)
	req.Header.Set("Authorization", header)
}
