package licensor_test

import (
	"crypto/rand"

	"github.com/ambitiousfew/licensor"
	"github.com/dchest/uniuri"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keys", func() {

	var k *licensor.PrivateKey

	BeforeEach(func() {
		var err error
		k, err = licensor.NewPrivateKey()
		Ω(err).To(BeNil())
	})

	It("should test private key bytes", func() {
		b, err := k.ToBytes()
		Ω(err).To(BeNil())
		k1, err := licensor.PrivateKeyFromBytes(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k))

		invalidBytes := make([]byte, 42)
		_, err = rand.Read(invalidBytes)
		Ω(err).To(BeNil())
		k2, err := licensor.PrivateKeyFromBytes(invalidBytes)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test private key b64", func() {
		b, err := k.ToB64String()
		Ω(err).To(BeNil())
		k1, err := licensor.PrivateKeyFromB64String(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k))

		invalidB64Str := uniuri.NewLen(42)
		k2, err := licensor.PrivateKeyFromB64String(invalidB64Str)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test private key b32", func() {
		b, err := k.ToB32String()
		Ω(err).To(BeNil())
		k1, err := licensor.PrivateKeyFromB32String(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k))

		invalidB32Str := uniuri.NewLen(42)
		k2, err := licensor.PrivateKeyFromB32String(invalidB32Str)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test private key hex", func() {
		b, err := k.ToHexString()
		Ω(err).To(BeNil())
		k1, err := licensor.PrivateKeyFromHexString(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k))

		invalidB32Str := uniuri.NewLen(42)
		k2, err := licensor.PrivateKeyFromHexString(invalidB32Str)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test pubic key bytes", func() {
		b := k.GetPublicKey().ToBytes()
		k1, err := licensor.PublicKeyFromBytes(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k.GetPublicKey()))

		invalidBytes := make([]byte, 42)
		_, err = rand.Read(invalidBytes)
		Ω(err).To(BeNil())
		k2, err := licensor.PublicKeyFromBytes(invalidBytes)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test pubic key b64", func() {
		b := k.GetPublicKey().ToB64String()
		k1, err := licensor.PublicKeyFromB64String(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k.GetPublicKey()))

		invalidB64Str := uniuri.NewLen(42)
		k2, err := licensor.PublicKeyFromB64String(invalidB64Str)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test pubic key b32", func() {
		b := k.GetPublicKey().ToB32String()
		k1, err := licensor.PublicKeyFromB32String(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k.GetPublicKey()))

		invalidB32Str := uniuri.NewLen(42)
		k2, err := licensor.PublicKeyFromB32String(invalidB32Str)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

	It("should test pubic key hex", func() {
		b := k.GetPublicKey().ToHexString()
		k1, err := licensor.PublicKeyFromHexString(b)
		Ω(err).To(BeNil())
		Ω(k1).To(Equal(k.GetPublicKey()))

		invalidHexStr := uniuri.NewLen(42)
		k2, err := licensor.PublicKeyFromHexString(invalidHexStr)
		Ω(err).To(HaveOccurred())
		Ω(k2).To(BeNil())
	})

})
