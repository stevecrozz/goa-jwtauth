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
	"github.com/rightscale/goa-jwtauth"
)

var _ = Describe("jwtauth middleware", func() {
	Context("error handling", func() {
		var stack goa.Handler
		var resp *httptest.ResponseRecorder
		var req *http.Request

		BeforeEach(func() {
			resp = httptest.NewRecorder()
			req, _ = http.NewRequest("GET", "http://example.com/", nil)
			stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
				return nil
			}

			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			middleware := jwtauth.New(scheme, jwtauth.Load(hmacKey1))
			stack = middleware(stack)
		})

		It("rejects unknown issuers", func() {
			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			store := &jwtauth.NamedKeystore{}
			middleware := jwtauth.New(scheme, store)

			setBearerHeader(req, makeToken("suspicious-issuer", "", hmacKey1))

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(401))
		})

		It("fails when JWTSecurity.Location is unsupported", func() {
			scheme := &goa.JWTSecurity{In: goa.LocQuery, Name: "jwt"}
			store := &jwtauth.NamedKeystore{}
			middleware := jwtauth.New(scheme, store)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).Should(HaveResponseStatus(500))
		})

		It("converts issuers to string", func() {
			scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}
			middleware := jwtauth.New(scheme, jwtauth.Load(hmacKey1))
			claims := jwtpkg.MapClaims{}
			claims["iss"] = 7
			token := jwtpkg.NewWithClaims(jwtpkg.SigningMethodHS256, &claims)
			s, err := token.SignedString(hmacKey1)
			if err != nil {
				panic(err)
			}
			setBearerHeader(req, s)

			result := middleware(stack)(context.Background(), resp, req)

			Ω(result).ShouldNot(HaveOccurred())
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
func testShared(trusted, untrusted interface{}) {
	scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}

	var resp *httptest.ResponseRecorder
	var req *http.Request

	var stack goa.Handler
	var middleware goa.Middleware
	var claims jwtauth.Claims

	BeforeEach(func() {
		resp = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "http://example.com/", nil)
		stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			claims = jwtauth.ContextClaims(ctx)
			return nil
		}

		var key interface{}
		switch tk := trusted.(type) {
		case []byte:
			key = trusted
		case *rsa.PrivateKey:
			key = &tk.PublicKey
		case *ecdsa.PrivateKey:
			key = &tk.PublicKey
		default:
			panic("Unsupported key type for tests")
		}

		middleware = jwtauth.New(scheme, jwtauth.Load(key))
	})

	AfterEach(func() {
		claims = nil
	})

	It("accepts requests that lack tokens", func() {
		result := middleware(stack)(context.Background(), resp, req)
		Ω(result).ShouldNot(HaveOccurred())
		Ω(claims).Should(HaveLen(0))
	})

	It("accepts valid tokens", func() {
		setBearerHeader(req, makeToken("alice", "bob", trusted))

		result := middleware(stack)(context.Background(), resp, req)

		Ω(result).ShouldNot(HaveOccurred())
		Ω(claims.String("sub")).Should(Equal("bob"))
	})

	It("rejects modified tokens", func() {
		bad := modifyToken(makeToken("alice", "bob", trusted))
		setBearerHeader(req, bad)

		result := middleware(stack)(context.Background(), resp, req)

		Ω(result).Should(HaveResponseStatus(401))
		Ω(claims).Should(HaveLen(0))
	})

	It("rejects untrusted tokens", func() {
		setBearerHeader(req, makeToken("_", "alice", untrusted))

		result := middleware(stack)(context.Background(), resp, req)

		Ω(result).Should(HaveResponseStatus(401))
		Ω(claims).Should(HaveLen(0))
	})

	It("rejects expired tokens", func() {
		iat := time.Now().Add(-time.Hour)
		exp := iat.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", "_", trusted, iat, iat, exp)
		setBearerHeader(req, bad)

		result := middleware(stack)(context.Background(), resp, req)

		Ω(result).Should(HaveResponseStatus(401))
		Ω(claims).Should(HaveLen(0))
	})

	It("rejects not-yet-valid tokens", func() {
		iat := time.Now()
		nbf := iat.Add(time.Minute)
		exp := nbf.Add(time.Minute)
		bad := makeTokenWithTimestamps("_", "_", trusted, iat, nbf, exp)
		setBearerHeader(req, bad)

		result := middleware(stack)(context.Background(), resp, req)

		Ω(result).Should(HaveResponseStatus(401))
		Ω(claims).Should(HaveLen(0))
	})
}
