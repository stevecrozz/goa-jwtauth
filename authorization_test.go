package jwtauth_test

import (
	"net/http"
	"net/http/httptest"

	"golang.org/x/net/context"

	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwt "github.com/xeger/goa-jwtauth"
)

var _ = Describe("Authorization()", func() {
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
		authentication := jwt.Authentication(scheme, hmacKey1)
		authorization := jwt.Authorization(scheme, "scopes")
		stack = authentication(authorization(stack))
	})

	Context("given no required scopes", func() {
		It("passes", func() {
			result := stack(context.Background(), resp, req)

			Ω(result).ShouldNot(HaveOccurred())
		})
	})

	Context("given a required scope", func() {
		ctx := context.Background()
		ctx = goa.WithRequiredScopes(ctx, []string{"read"})

		It("responds with 403 Forbidden", func() {
			result := stack(ctx, resp, req)

			Ω(result).Should(HaveOccurred())
		})

		It("passes authorized requests", func() {
			setBearerHeader(req, makeToken("good-issuer", "good-subject", hmacKey1, "read"))

			result := stack(ctx, resp, req)

			Ω(result).ShouldNot(HaveOccurred())
		})

		It("forbids unauthorized requests", func() {
			setBearerHeader(req, makeToken("good-issuer", "bad-subject", hmacKey1))

			result := stack(ctx, resp, req)

			Ω(result).Should(HaveOccurred())
		})
	})
})
