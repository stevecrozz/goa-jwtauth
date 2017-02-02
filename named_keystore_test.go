package jwtauth_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	jwt "github.com/xeger/goa-middleware-jwt"
)

var _ = Describe("NamedKeystore", func() {
	var store *jwt.NamedKeystore

	BeforeEach(func() {
		store = &jwt.NamedKeystore{}
		Ω(store.Trust("moo", hmacKey1)).ShouldNot(HaveOccurred())
	})

	It("initializes itself", func() {
		zero := &jwt.NamedKeystore{}
		Ω(zero.Get("moo")).Should(BeNil())
		Expect(func() {
			zero.RevokeTrust("moo")
		}).NotTo(Panic())
	})

	Context("AddTrust()", func() {
		It("accepts bytes", func() {
			Ω(store.Trust("bah", hmacKey2)).ShouldNot(HaveOccurred())
		})

		It("accepts public keys", func() {
			Ω(store.Trust("bah", &rsaKey1.PublicKey)).ShouldNot(HaveOccurred())
			Ω(store.Trust("bah", &rsaKey1.PublicKey)).ShouldNot(HaveOccurred())
		})

		It("tolerates idempotent double-add", func() {
			Ω(store.Trust("moo", hmacKey1)).ShouldNot(HaveOccurred())
			Ω(store.Get("moo")).Should(Equal(hmacKey1))
		})

		It("rejects double-add", func() {
			Ω(store.Trust("moo", hmacKey2)).Should(HaveOccurred())
		})

		It("rejects unknown types", func() {
			Ω(store.Trust("bah", 666)).Should(HaveOccurred())
		})

		It("converts strings to bytes", func() {
			Ω(store.Trust("bah", "this should be bytes")).ShouldNot(HaveOccurred())
		})

		It("converts private keys to public", func() {
			Ω(store.Trust("bah", rsaKey1)).ShouldNot(HaveOccurred())
			Ω(store.Trust("oink", ecKey1)).ShouldNot(HaveOccurred())
		})
	})

	Context("RevokeTrust()", func() {
		It("removes the specified issuer", func() {
			Ω(store.Get("moo")).ShouldNot(Equal(nil))
			store.RevokeTrust("moo")
			Ω(store.Get("moo")).Should(BeNil())
		})
	})

	Context("Get()", func() {
		It("returns a key for specified issuer", func() {
			Ω(store.Get("moo")).Should(Equal(hmacKey1))
			Ω(store.Get("bah")).Should(BeNil())
		})
	})
})
