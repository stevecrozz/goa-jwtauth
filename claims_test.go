package jwtauth_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rightscale/goa-jwtauth"
)

type bogusStringer struct {
}

func (bs bogusStringer) String() string {
	return fmt.Sprintf("%T", bs)
}

var _ = Describe("Claims", func() {
	It("handles type conversions", func() {
		claims := jwtauth.Claims{}

		claims["foo"] = bogusStringer{}
		Expect(claims.String("foo")).To(Equal("jwtauth_test.bogusStringer"))
		claims["foo"] = 42
		Expect(claims.String("foo")).To(Equal("42"))

		claims["foo"] = "bar"
		Expect(claims.Strings("foo")).To(Equal([]string{"bar"}))
		claims["foo"] = []string{"bar", "baz"}
		Expect(claims.Strings("foo")).To(Equal([]string{"bar", "baz"}))

		claims["foo"] = true
		Expect(claims.Bool("foo")).To(Equal(true))
		claims["foo"] = "True"
		Expect(claims.Bool("foo")).To(Equal(true))
		claims["foo"] = "f"
		Expect(claims.Bool("foo")).To(Equal(false))
		claims["foo"] = "Fal"
		Expect(claims.Bool("foo")).To(Equal(false))
		falseNumbers := []interface{}{
			0, -1,
			uint(0),
			int64(0),
			uint64(0),
			float32(0),
			float64(0),
		}
		trueNumbers := []interface{}{
			1, 42,
			uint(1),
			int64(1),
			uint64(1),
			float32(1),
			float64(1),
		}
		for _, n := range falseNumbers {
			claims["foo"] = n
			Expect(claims.Bool("foo")).To(Equal(false))
			Expect(claims.Int("foo")).To(BeNumerically("<=", 0))
		}
		for _, n := range trueNumbers {
			claims["foo"] = n
			Expect(claims.Bool("foo")).To(Equal(true))
			Expect(claims.Int("foo")).To(BeNumerically(">", int64(0)))
		}

		claims["foo"] = "0"
		Expect(claims.Int("foo")).To(Equal(int64(0)))
		claims["foo"] = "42"
		Expect(claims.Int("foo")).To(Equal(int64(42)))
		claims["foo"] = float32(42.0)
		Expect(claims.Int("foo")).To(Equal(int64(42)))
		claims["foo"] = float64(42.0)
		Expect(claims.Int("foo")).To(Equal(int64(42)))

		now := time.Now().Unix()
		claims["foo"] = now
		Expect(claims.Time("foo").Unix()).To(Equal(now))
	})

	It("handles standard claims", func() {
		epoch := time.Unix(0, 0).UTC()
		then := time.Unix(0xFFFFFFFF, 0).UTC()

		claims := jwtauth.Claims{
			"iss": "Issuer",
			"sub": "Subject",
			"iat": 0,
			"nbf": 0,
			"exp": then.Unix(),
		}

		Expect(claims.Issuer()).To(Equal("Issuer"))
		Expect(claims.Subject()).To(Equal("Subject"))
		Expect(claims.IssuedAt()).To(Equal(epoch))
		Expect(claims.NotBefore()).To(Equal(epoch))
		Expect(claims.ExpiresAt()).To(Equal(then.UTC()))
	})
})
