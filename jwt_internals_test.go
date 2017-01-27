package jwt

import (
	jwt "github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type bogusClaims struct{}

func (bc *bogusClaims) Valid() error {
	return nil
}

var _ = Describe("identifyIssuer()", func() {
	It("accepts jwt.StandardClaims", func() {
		claims := &jwt.StandardClaims{}
		token := &jwt.Token{Claims: claims}
		_, err := identifyIssuer(token)
		Ω(err).ShouldNot(HaveOccurred())
	})

	It("rejects unknown claims types", func() {
		claims := &bogusClaims{}
		token := &jwt.Token{Claims: claims}
		_, err := identifyIssuer(token)
		Ω(err).Should(HaveOccurred())
	})
})
