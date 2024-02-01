package lk_test

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/ambitiousfew/licensor"
)

type MyLicence struct {
	Email string    `json:"email"`
	End   time.Time `json:"end"`
}

// Example_complete creates a new license and validate it.
func Example_complete() {
	// create a new Private key:
	privateKey, err := lk.NewPrivateKey()
	if err != nil {
		log.Fatal(err)

	}

	// create a license document:
	doc := MyLicence{
		"test@example.com",
		time.Now().Add(time.Hour * 24 * 365), // 1 year
	}

	// marshall the document to json bytes:
	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)

	}

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal(err)

	}

	// encode the new license to b64, this is what you give to your customer.
	str64, err := license.ToB64String()
	if err != nil {
		log.Fatal(err)

	}
	fmt.Println(str64)

	// get the public key. The public key should be hardcoded in your app
	// to check licences. Do not distribute the private key!
	publicKey := privateKey.GetPublicKey()

	// validate the license:
	if ok, err := license.Verify(publicKey); err != nil {
		log.Fatal(err)
	} else if !ok {
		log.Fatal("Invalid license signature")
	}

	// unmarshal the document and check the end date:
	res := MyLicence{}
	if err := json.Unmarshal(license.Data, &res); err != nil {
		log.Fatal(err)
	} else if res.End.Before(time.Now()) {
		log.Fatalf("License expired on: %s", res.End.String())
	} else {
		fmt.Printf(`Licensed to %s until %s \n`, res.Email, res.End.Format("2006-01-02"))
	}
}

// Example_licenseGeneration shows how to create a license file from a private
// key.
func Example_licenseGeneration() {

	// a base32 encoded private key generated by `lkgen gen`
	// note that you might prefer reading it from a file...
	const privateKeyBase32 = "FD7YCAYBAEFXA22DN5XHIYLJNZSXEAP7QIAACAQBANIHKYQBBIAACAKEAH7YIAAAAAFP7AYFAEBP7BQAAAAP7GP7QIAWCBCRKQVWKPT7UJDNP4LB5TXEQMO7EYEGDCE42KVBDNEGRIYIIJFBIWIVB6T6ZTKLSYSGK54DZ5VX6M5SJHBYZU2JXUFXJI25L2JJKJW4RL7UL2XBDT4GKYZ5IS6IWBCN7CWTMVBCBHJMH3RHZ5BVGVAY66MQAEYQEPSS2ANTYZIWXWSGIUJW3MDOO335JK3D4N3IV4L5UTAQMLS5YC7QASCAAUOHTZ5ZCCCYIBNCWBELBMAA===="

	// Here we use a struct that is marshalled to json,
	// but ultimatly all you need is a []byte.
	doc := struct {
		Email string    `json:"email"`
		End   time.Time `json:"end"`
	}{
		"test@example.com",
		time.Now().Add(time.Hour * 24 * 365), // 1 year
	}

	// marshall the document to []bytes (this is the data that our license
	// will contain):
	docBytes, err := json.Marshal(doc)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the private key:
	privateKey, err := lk.PrivateKeyFromB32String(privateKeyBase32)
	if err != nil {
		log.Fatal(err)
	}

	// generate your license with the private key and the document:
	license, err := lk.NewLicense(privateKey, docBytes)
	if err != nil {
		log.Fatal(err)

	}
	// the b32 representation of our license, this is what you give to
	// your customer.
	licenseB32, err := license.ToB32String()
	if err != nil {
		log.Fatal(err)

	}
	fmt.Println(licenseB32)
}

// Example_licenseVerification validates a previously generated license with
// a public key.
func Example_licenseVerification() {

	// A previously generated licence b32 encoded. In real life you should read
	// it from a file at the beginning of your program and check it
	// before doing anything else...
	const licenseB32 = "FT7YOAYBAEDUY2LDMVXHGZIB76EAAAIDAECEIYLUMEAQUAABAFJAD74EAAAQCUYB76CAAAAABL7YGBIBAL7YMAAAAD73H74IAFEHWITFNVQWS3BCHIRHIZLTORAGK6DBNVYGYZJOMNXW2IRMEJSW4ZBCHIRDEMBRHAWTCMBNGI3FIMJSHIYTSORTGMXDOMBZG43TIMJYHAVTAMR2GAYCE7IBGEBAPXB37ROJCUOYBVG4LAL3MSNKJKPGIKNT564PYK5X542NH62V7TAUEYHGLEOPZHRBAPH7M4SC55OHAEYQEXMKGG3JPO6BSHTDF3T5H6T42VUD7YAJ3TY5AP5MDE5QW4ZYWMSAPEK24HZOUXQ3LJ5YY34XYPVXBUAA===="

	// the public key b32 encoded from the private key using:
	// `lkgen pub my_private_key_file`. It should be
	// hardcoded somewhere in your app.
	const publicKeyBase32 = "ARIVIK3FHZ72ERWX6FQ6Z3SIGHPSMCDBRCONFKQRWSDIUMEEESQULEKQ7J7MZVFZMJDFO6B46237GOZETQ4M2NE32C3UUNOV5EUVE3OIV72F5LQRZ6DFMM6UJPELARG7RLJWKQRATUWD5YT46Q2TKQMPPGIA===="

	// Unmarshal the public key
	publicKey, err := lk.PublicKeyFromB32String(publicKeyBase32)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal the customer license:
	license, err := lk.LicenseFromB32String(licenseB32)
	if err != nil {
		log.Fatal(err)
	}

	// validate the license signature:
	if ok, err := license.Verify(publicKey); err != nil {
		log.Fatal(err)
	} else if !ok {
		log.Fatal("Invalid license signature")
	}

	result := struct {
		Email string    `json:"email"`
		End   time.Time `json:"end"`
	}{}

	// unmarshal the document:
	if err := json.Unmarshal(license.Data, &result); err != nil {
		log.Fatal(err)
	}

	// Now you just have to check the end date and if it before time.Now(),
	// then you can continue!
	// if result.End.Before(time.Now()) {
	// 	log.Fatal("License expired on: %s", result.End.Format("2006-01-02"))
	// } else {
	// 	fmt.Printf(`Licensed to %s until %s`, result.Email, result.End.Format("2006-01-02"))
	// }

}
