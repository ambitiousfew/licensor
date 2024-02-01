package licensor_test

import (
	"bytes"
	"crypto/rand"

	"github.com/ambitiousfew/licensor"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("License", func() {

	var privateKey *licensor.PrivateKey
	var wrongKey *licensor.PrivateKey
	var license *licensor.License
	var b []byte

	BeforeEach(func() {
		var err error

		privateKey, err = licensor.NewPrivateKey()
		Ω(err).To(BeNil())
		Ω(privateKey).ToNot(BeNil())

		wrongKey, err = licensor.NewPrivateKey()
		Ω(err).To(BeNil())
		Ω(privateKey).ToNot(BeNil())

		b = make([]byte, 100)
		_, err = rand.Read(b)
		Ω(err).To(BeNil())

		license, err = licensor.NewLicense(privateKey, b)
		Ω(err).To(BeNil())
		Ω(license).ToNot(BeNil())
		ok, err := license.Verify(privateKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeTrue())
	})

	It("should pass the example", func() {
		Example_complete()
		Example_licenseGeneration()
		Example_licenseVerification()
	})

	It("should test a license with bytes", func() {
		b2, err := license.ToBytes()
		Ω(err).To(BeNil())
		l2, err := licensor.LicenseFromBytes(b2)
		Ω(err).To(BeNil())
		ok, err := l2.Verify(privateKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeTrue())
		Ω(bytes.Equal(license.Data, l2.Data)).To(BeTrue())

	})

	It("should not validate with wrong key", func() {
		ok, err := license.Verify(wrongKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeFalse())
	})

	It("should test a license with b64", func() {
		b2, err := license.ToB64String()
		Ω(err).To(BeNil())
		l2, err := licensor.LicenseFromB64String(b2)
		Ω(err).To(BeNil())
		ok, err := l2.Verify(privateKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeTrue())
		Ω(bytes.Equal(license.Data, l2.Data)).To(BeTrue())

	})

	It("should test a license with b32", func() {
		b2, err := license.ToB32String()
		Ω(err).To(BeNil())
		l2, err := licensor.LicenseFromB32String(b2)
		Ω(err).To(BeNil())
		ok, err := l2.Verify(privateKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeTrue())
		Ω(bytes.Equal(license.Data, l2.Data)).To(BeTrue())

	})

	It("should test a license with hex", func() {
		b2, err := license.ToHexString()
		Ω(err).To(BeNil())
		l2, err := licensor.LicenseFromHexString(b2)
		Ω(err).To(BeNil())
		ok, err := l2.Verify(privateKey.GetPublicKey())
		Ω(err).To(BeNil())
		Ω(ok).To(BeTrue())
		Ω(bytes.Equal(license.Data, l2.Data)).To(BeTrue())

	})

})
