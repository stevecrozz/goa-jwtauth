package jwtauth_test

import (
	"net/http"
	"net/http/httptest"

	"golang.org/x/net/context"

	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/goa-jwtauth"
)

var _ = Describe("New()", func() {
	var resp *httptest.ResponseRecorder
	var req *http.Request

	var store jwtauth.Keystore
	var stack goa.Handler
	var claims jwtauth.Claims

	BeforeEach(func() {
		resp = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "http://example.com/", nil)
		store = &jwtauth.SimpleKeystore{hmacKey1}
		stack = func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			claims = jwtauth.ContextClaims(ctx)
			return nil
		}
	})

	It("applies options", func() {
		var calledAuth, calledExtract bool
		auth := func(context.Context, jwtauth.Claims) error {
			calledAuth = true
			return nil
		}
		extract := func(*goa.JWTSecurity, *http.Request) (string, error) {
			calledExtract = true
			return "", nil
		}

		middleware := jwtauth.New(commonScheme, store, jwtauth.Extraction(extract), jwtauth.Authorization(auth))

		middleware(stack)(context.Background(), resp, req)

		Ω(calledAuth).Should(BeTrue())
		Ω(calledExtract).Should(BeTrue())
	})
})

var _ = Describe("NewToken()", func() {
	It("rejects unknown key types", func() {
		_, err := jwtauth.NewToken(42.0, jwtauth.Claims{})
		Ω(err).Should(HaveOccurred())
	})

	It("accepts known key types", func() {

	})
})
