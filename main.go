package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
)

func main() {
	var genRoot bool

	flag.BoolVar(&genRoot, "genroot", false, "generate root certificate and exit (default false).")
	flag.Parse()

	if genRoot {
		generateRootCa()
	}
}

func generateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// createRequest generates a certificate request.
//
// org - legal entity name
// country - country
// ou - department or web-site
// cn - description
// privateKey - RSA private key
func createRequest(org, country, ou, cn string, privateKey *rsa.PrivateKey, parent *x509.Certificate) (*x509.Certificate, error) {

}
