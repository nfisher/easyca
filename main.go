package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"time"
)

const (
	rootPath     = "/"
	certFormPath = "/cert/new"
	certPostPath = "/cert/"

	defaultBits = 2048

	countryField = "country"
	cnField      = "cn"
	ouField      = "ou"

	tenYears = time.Hour * 24 * 365 * 10

	certRequestForm = `<!doctype html>
<head>
<title>Create Certificate</title>
<style>
label {
	display:block;
	padding:0.25em 0;
	width:20em;
}
input {
	width:20em;
}
</style>
</head>
<body>
<form method=post action="/cert/">
<p>
<label for=cn>Hostname (CN)</label>
<input type=text name=cn>
</p>
<p>
<label for=country>Country</label>
<input type=text name=country id=country>
</p>
<p>
<label for=ou>Department (OU)</label>
<input type=text name=ou>
</p>
<p>
<input type=submit value="Submit">
</p>
</form>
</body>`
)

// lazy request log wrapper should record response code as well.
func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler.ServeHTTP(w, r)
		log.Printf("%s %s %s %v", r.RemoteAddr, r.Method, html.EscapeString(r.URL.String()), time.Now().Sub(start))
	})
}

func runServer(listenAddr string) {
	http.HandleFunc(rootPath, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, certFormPath, http.StatusFound)
	})

	http.HandleFunc(certFormPath, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(certRequestForm))
	})

	// take form data generate a key and ceritificate and output to the browser in PEM format.
	http.HandleFunc(certPostPath, func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			log.Panicf("error parsing form data - %v", err)
		}

		privateKey, err := generateKey(defaultBits)
		if err != nil {
			log.Panicf("error generating private key - %v", err)
		}

		w.Write(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))

		cn := html.EscapeString(r.Form.Get(cnField))
		country := html.EscapeString(r.Form.Get(countryField))
		ou := html.EscapeString(r.Form.Get(ouField))
		org := cn + " root CA"

		template := createTemplate(org, country, ou, cn, true)

		der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
		if err != nil {
			log.Panicf("error creating certificate - %v", err)
		}

		fmt.Fprintln(w, "")

		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	})

	log.Fatal(http.ListenAndServe(listenAddr, Log(http.DefaultServeMux)))
}

func main() {
	var listenAddr string
	var genRoot bool

	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "default listening address (default 127.0.0.1:8080).")
	flag.BoolVar(&genRoot, "genroot", false, "generate root certificate and exit (default false).")
	flag.Parse()

	log.Printf("server listening on %v.\n", listenAddr)
	runServer(listenAddr)
}

func generateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// createTemplate generates a certificate request.
//
// org - legal entity name
// country - country
// ou - department or web-site
// cn - description
// isCa - if true this will be a self-signed certificate.
//
func createTemplate(org, country, ou, cn string, isCa bool) (certificate *x509.Certificate) {
	now := time.Now()

	r := mrand.New(mrand.NewSource(now.UnixNano()))
	maxInt := big.NewInt(math.MaxInt64)
	serialNumber := big.NewInt(0)
	serialNumber = serialNumber.Rand(r, maxInt)

	certificate = &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Country:      []string{country},
			Organization: []string{org},
		},
		NotBefore: now,
		NotAfter:  now.Add(tenYears),
	}

	if isCa {
		certificate.BasicConstraintsValid = true
		certificate.IsCA = true
		certificate.KeyUsage = x509.KeyUsageCertSign
	}

	return
}
