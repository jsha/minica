package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}

type issuer struct {
	key  crypto.Signer
	cert *x509.Certificate
}

// Subject represents a JSON description of a PKIX Name
type Subject struct {
	CommonName         string        `json:"common_name,omitempty"`
	SerialNumber       string        `json:"serial_number,omitempty"`
	Country            string        `json:"country,omitempty"`
	Organization       string        `json:"organization,omitempty"`
	OrganizationalUnit string        `json:"organizational_unit,omitempty"`
	Locality           string        `json:"locality,omitempty"`
	Province           string        `json:"province,omitempty"`
	StreetAddress      string        `json:"street_address,omitempty"`
	PostalCode         string        `json:"postal_code,omitempty"`
	Names              []interface{} `json:"names,omitempty"`
	ExtraNames         []interface{} `json:"extra_names,omitempty"`
}

func parseSubject(jsonFile string) (pkix.Name, error) {
	raw, readErr := ioutil.ReadFile(jsonFile)
	if readErr != nil {
		return pkix.Name{}, readErr
	}
	var subject Subject
	err := json.Unmarshal(raw, &subject)
	if err != nil {
		return pkix.Name{}, fmt.Errorf("parsing subject JSON file: %s", err)
	}

	n := pkix.Name{
		CommonName:         subject.CommonName,
		SerialNumber:       subject.SerialNumber,
		Country:            []string{subject.Country},
		Organization:       []string{subject.Organization},
		OrganizationalUnit: []string{subject.OrganizationalUnit},
		Locality:           []string{subject.Locality},
		Province:           []string{subject.Province},
		StreetAddress:      []string{subject.StreetAddress},
		PostalCode:         []string{subject.PostalCode},
	}
	return n, nil
}

func getIssuer(keyFile, certFile string, subjectFile string, autoCreate bool) (*issuer, error) {
	keyContents, keyErr := ioutil.ReadFile(keyFile)
	certContents, certErr := ioutil.ReadFile(certFile)
	if os.IsNotExist(keyErr) && os.IsNotExist(certErr) {
		err := makeIssuer(keyFile, certFile, subjectFile)
		if err != nil {
			return nil, err
		}
		return getIssuer(keyFile, certFile, subjectFile, false)
	} else if keyErr != nil {
		return nil, fmt.Errorf("%s (but %s exists)", keyErr, certFile)
	} else if certErr != nil {
		return nil, fmt.Errorf("%s (but %s exists)", certErr, keyFile)
	}
	key, err := readPrivateKey(keyContents)
	if err != nil {
		return nil, fmt.Errorf("reading private key from %s: %s", keyFile, err)
	}

	cert, err := readCert(certContents)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate from %s: %s", certFile, err)
	}

	equal, err := publicKeysEqual(key.Public(), cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("comparing public keys: %s", err)
	} else if !equal {
		return nil, fmt.Errorf("public key in CA certificate %s doesn't match private key in %s",
			certFile, keyFile)
	}
	return &issuer{key, cert}, nil
}

func readPrivateKey(keyContents []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type != "RSA PRIVATE KEY" && block.Type != "ECDSA PRIVATE KEY" {
		return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func readCert(certContents []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certContents)
	if block == nil {
		return nil, fmt.Errorf("no PEM found")
	} else if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("incorrect PEM type %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func makeIssuer(keyFile, certFile string, subjectFile string) error {
	key, err := makeKey(keyFile)
	if err != nil {
		return err
	}
	_, err = makeRootCert(key, certFile, subjectFile)
	if err != nil {
		return err
	}
	return nil
}

func makeKey(filename string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func makeRootCert(key crypto.Signer, filename string, subjectFile string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	subject := func() pkix.Name {
		if subjectFile == "" {
			return pkix.Name{
				CommonName: "minica Root CA " + hex.EncodeToString(serial.Bytes()[:3]),
			}
		}

		subject, err := parseSubject(subjectFile)
		if err != nil {
			log.Fatal(err)
		}
		return subject
	}()
	log.Printf("using Root CA subject %s", subject)

	template := &x509.Certificate{
		Subject:      subject,
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(100, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseIPs(ipAddresses []string) ([]net.IP, error) {
	var parsed []net.IP
	for _, s := range ipAddresses {
		p := net.ParseIP(s)
		if p == nil {
			return nil, fmt.Errorf("invalid IP address %s", s)
		}
		parsed = append(parsed, p)
	}
	return parsed, nil
}

func publicKeysEqual(a, b interface{}) (bool, error) {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, err
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, err
	}
	return bytes.Compare(aBytes, bBytes) == 0, nil
}

func sign(iss *issuer, domains []string, ipAddresses []string) (*x509.Certificate, error) {
	var cn string
	if len(domains) > 0 {
		cn = domains[0]
	} else if len(ipAddresses) > 0 {
		cn = ipAddresses[0]
	} else {
		return nil, fmt.Errorf("must specify at least one domain name or IP address")
	}
	var cnFolder = strings.Replace(cn, "*", "_", -1)
	err := os.Mkdir(cnFolder, 0700)
	if err != nil && !os.IsExist(err) {
		return nil, err
	}
	key, err := makeKey(fmt.Sprintf("%s/key.pem", cnFolder))
	if err != nil {
		return nil, err
	}
	parsedIPs, err := parseIPs(ipAddresses)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		DNSNames:    domains,
		IPAddresses: parsedIPs,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(90, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, iss.cert, key.Public(), iss.key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(fmt.Sprintf("%s/cert.pem", cnFolder), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	err = pem.Encode(file, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func split(s string) (results []string) {
	if len(s) > 0 {
		return strings.Split(s, ",")
	}
	return nil
}

func main2() error {
	var caKey = flag.String("ca-key", "minica-key.pem", "Root private key filename, PEM encoded.")
	var caCert = flag.String("ca-cert", "minica.pem", "Root certificate filename, PEM encoded.")
	var subjectFile = flag.String("subject-file", "", "JSON file with subject information (optional).")
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, `
Minica is a simple CA intended for use in situations where the CA operator
also operates each host where a certificate will be used. It automatically
generates both a key and a certificate when asked to produce a certificate.
It does not offer OCSP or CRL services. Minica is appropriate, for instance,
for generating certificates for RPC systems or microservices.

On first run, minica will generate a keypair and a root certificate in the
current directory, and will reuse that same keypair and root certificate
unless they are deleted.

Optionally, you can provide a JSON file for the root CA's subject:

{
	"common_name": "",
	"serial_number": "",
	"country": "",
	"organization": "",
	"organizational_unit": "",
	"locality": "",
	"province": "",
	"street_address": "",
	"postal_code": "",
	"names": [],
	"extra_names": []
}

On each run, minica will generate a new keypair and sign an end-entity (leaf)
certificate for that keypair. The certificate will contain a list of DNS names
and/or IP addresses from the command line flags. The key and certificate are
placed in a new directory whose name is chosen as the first domain name from
the certificate, or the first IP address if no domain names are present. It
will not overwrite existing keys or certificates.
`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *domains == "" && *ipAddresses == "" {
		flag.Usage()
		os.Exit(1)
	}

	issuer, err := getIssuer(*caKey, *caCert, *subjectFile, true)
	if err != nil {
		return err
	}
	_, err = sign(issuer, split(*domains), split(*ipAddresses))
	return err
}
