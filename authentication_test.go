package jwtauth_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"time"

	"golang.org/x/net/context"

	jwtpkg "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwt "github.com/xeger/goa-middleware-jwt"
)

var _ = Describe("Authentication()", func() {
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
			middleware := jwt.AuthenticationWithKeystore(scheme, store)

			setBearerHeader(req, makeToken("suspicious-issuer", "", hmacKey1))

			result := middleware(handler)(context.Background(), resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("fails when JWTSecurity.Location is unsupported", func() {
			scheme := &goa.JWTSecurity{In: goa.LocQuery, Name: "jwt"}
			store := &jwt.NamedKeystore{}
			middleware := jwt.AuthenticationWithKeystore(scheme, store)

			result := middleware(handler)(context.Background(), resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("rejects malformed issuers", func() {
			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			middleware := jwt.Authentication(scheme, hmacKey1)
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

		middleware = jwt.Authentication(scheme, key)

		token = nil
	})

	It("accepts requests that lack tokens", func() {
		result := middleware(handler)(context.Background(), resp, req)
		Ω(result).ShouldNot(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("accepts valid tokens", func() {
		setBearerHeader(req, makeToken("_", "", trusted))

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).ShouldNot(HaveOccurred())
		Ω(token).ShouldNot(BeNil())
	})

	It("rejects modified tokens", func() {
		bad := modifyToken(makeToken("_", "", trusted))
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects untrusted tokens", func() {
		setBearerHeader(req, makeToken("_", "_", untrusted))

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects expired tokens", func() {
		iat := time.Now().Add(-time.Hour)
		exp := iat.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", "_", trusted, iat, iat, exp)
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})

	It("rejects not-yet-valid tokens", func() {
		iat := time.Now()
		nbf := iat.Add(time.Minute)
		exp := nbf.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", "_", trusted, iat, nbf, exp)
		setBearerHeader(req, bad)

		result := middleware(handler)(context.Background(), resp, req)

		Ω(result).Should(HaveOccurred())
		Ω(token).Should(BeNil())
	})
}
