package jwtauth

import (
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type trivialStringer struct{}

func (s trivialStringer) String() string {
	return fmt.Sprintf("%T", s)
}

var _ = Describe("identifyIssuer()", func() {
	It("accepts tokens with no issuer", func() {
		claims := jwt.MapClaims{}
		token := &jwt.Token{Claims: claims}
		issuer, err := identifyIssuer(token)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(issuer).Should(Equal(""))
	})

	It("converts non-string issuer to string", func() {
		claims := jwt.MapClaims{"iss": 42}
		token := &jwt.Token{Claims: claims}
		issuer, err := identifyIssuer(token)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(issuer).Should(Equal("42"))

		claims["iss"] = &trivialStringer{}
		issuer, err = identifyIssuer(token)
		Ω(err).ShouldNot(HaveOccurred())
		Ω(issuer).Should(Equal("jwtauth.trivialStringer"))
	})

	It("rejects unknown claims types", func() {
		claims := &jwt.StandardClaims{}
		token := &jwt.Token{Claims: claims}
		_, err := identifyIssuer(token)
		Ω(err).Should(HaveOccurred())
	})
})
