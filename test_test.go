package jwtauth_test

import (
	"github.com/goadesign/goa"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwt "github.com/xeger/goa-middleware-jwt"
)

var _ = Describe("TestMiddleware()", func() {
	scheme := &goa.JWTSecurity{In: goa.LocHeader, Name: "Authorization"}

	It("returns a middleware", func() {
		mw := jwt.TestMiddleware(scheme)
		Ω(mw).ShouldNot(BeNil())
	})
})

var _ = Describe("TestToken()", func() {
	It("returns a token", func() {
		tok := jwt.TestToken("iss", "alice")
		Ω(tok).ShouldNot(Equal(""))
	})

	It("adds issuer if none present", func() {
		tok := jwt.TestToken()
		Ω(tok).ShouldNot(Equal(""))
	})

	It("panics on invalid claims", func() {
		Expect(func() {
			illegal := make(chan int)
			jwt.TestToken("illegal", illegal)
		}).To(Panic())
	})
})
