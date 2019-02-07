package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
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

const (
	envPrivkeyPass      = "MINICA_KEY_PASSWORD"
	defaultCaNamePrefix = "minica"
)

type issuerCreationMode int

const (
	_ issuerCreationMode = iota //previous default => doCreate
	createAndEncrypt
	noAutoCreate
)

type autoCreateOpts struct {
	mode       issuerCreationMode
	namePrefix *string
	createOnly bool
}

// don't ask pass when reloading newly create key.
var keyPass []byte

func getPassword(confirm bool) (password []byte, err error) {
	err = nil
	if keyPass != nil {
		password = keyPass
		return
	}
	fromEnv, isSet := os.LookupEnv(envPrivkeyPass)
	if isSet {
		fmt.Println("Using password from environment.")
		password = []byte(fromEnv)
		return
	}
	//ensures that echo is turned back on in case of interrupt
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	previousState, err := terminal.GetState(syscall.Stdin)
	go func() {
		e := <-sigs
		if e != nil {
			fmt.Printf("Exiting on %v\n", e)
			_ = terminal.Restore(syscall.Stdout, previousState)
			os.Exit(1)
		}
	}()
	defer func() {
		close(sigs)
	}()

	fmt.Println("Please enter Private Key Password.")
	passwordFirst, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return
	}
	if !confirm {
		password = passwordFirst
		return
	}
	fmt.Println("Please confirm Private Key Password.")
	passwordConfirmation, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return
	}
	if bytes.Compare(passwordFirst, passwordConfirmation) == 0 {
		password = passwordFirst
		keyPass = password
		return
	}
	err = fmt.Errorf("passwords do not match")
	return
}
func getIssuer(keyFile, certFile string, acOpts autoCreateOpts) (*issuer, error) {
	keyContents, keyErr := ioutil.ReadFile(keyFile)
	certContents, certErr := ioutil.ReadFile(certFile)
	keyFileIsMissing := os.IsNotExist(keyErr)
	certFileIsMissing := os.IsNotExist(certErr)
	if keyFileIsMissing && certFileIsMissing {
		if acOpts.mode != noAutoCreate {
			err := makeIssuer(keyFile, certFile, acOpts)
			if err != nil {
				return nil, err
			}
			acOpts.mode = noAutoCreate
			acOpts.namePrefix = nil
			acOpts.createOnly = false
			return getIssuer(keyFile, certFile, acOpts)
		}
		return nil, fmt.Errorf("%s and %s do not exist and auto-create is turned off", keyFile, certFile)
	}
	if certFileIsMissing {
		return nil, fmt.Errorf("%s does not exist", certFile)
	}
	if keyFileIsMissing {
		return nil, fmt.Errorf("%s does not exist", keyFile)
	}
	if keyErr != nil {
		return nil, fmt.Errorf("%s (but %s exists)", keyErr, keyFile)
	}
	if certErr != nil {
		return nil, fmt.Errorf("%s (but %s exists)", certErr, certFile)
	}
	if acOpts.createOnly {
		return nil, fmt.Errorf("root CA already exists. It can't be created")
	}

	warnAboutUselessCreateOpts(&acOpts, "private key already exists")
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
	if x509.IsEncryptedPEMBlock(block) {
		if keyPass == nil {
			fmt.Println("Private Key is encrypted.")
		}

		password, err := getPassword(false)
		if err != nil {
			return nil, err
		}

		pemBytes, err := x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}

		block = &pem.Block{
			Bytes: pemBytes,
			Type:  block.Type,
		}
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

func makeIssuer(keyFile, certFile string, acOpts autoCreateOpts) error {
	encryptKey := acOpts.mode == createAndEncrypt
	if encryptKey {
		fmt.Println("Creating encrypted root CA...")
	} else {
		fmt.Println("Creating root CA...")
	}
	key, err := makeKey(keyFile, encryptKey)
	if err != nil {
		return err
	}
	_, err = makeRootCert(key, certFile, *acOpts.namePrefix)
	if err != nil {
		return err
	}
	return nil
}

func makeKey(filename string, encrypt bool) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	if err != nil {
		return nil, err
	}
	var password []byte
	if encrypt {
		password, err = getPassword(true)
		if err != nil {
			return nil, err
		}
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}
	if encrypt {
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, password, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}

	err = pem.Encode(file, block)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func makeRootCert(key crypto.Signer, filename string, caNamePrefix string) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	skid, err := calculateSKID(key.Public())
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("%s root ca %s", caNamePrefix, hex.EncodeToString(serial.Bytes()[:3])),
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(100, 0, 0),

		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
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

func calculateSKID(pubKey crypto.PublicKey) ([]byte, error) {
	spkiASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	_, err = asn1.Unmarshal(spkiASN1, &spki)
	if err != nil {
		return nil, err
	}
	skid := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return skid[:], nil
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
	key, err := makeKey(fmt.Sprintf("%s/key.pem", cnFolder), false)
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
	var domains = flag.String("domains", "", "Comma separated domain names to include as Server Alternative Names.")
	var ipAddresses = flag.String("ip-addresses", "", "Comma separated IP addresses to include as Server Alternative Names.")
	var caNamePrefix = flag.String("ca-name", defaultCaNamePrefix, "Prefix for name of Root CA")
	var disableAutoCreate = flag.Bool("no-auto", false, "Prevent automatic creation of root CA")
	var encryptCAKey = flag.Bool("encrypt-ca-key", false, fmt.Sprintf("Encrypt root CA private key (will ask password or use %s from env)", envPrivkeyPass))
	var rootCAOnly = flag.Bool("root-ca-only", false, "Only create root CA (no certificates)")
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
Private key file can be encrypted/password protected.
This automatic creation can be disabled to avoid creation of certificates not
signed by the expected key (after distribution of the root certificate).

On each run, minica will generate a new keypair and sign an end-entity (leaf)
certificate for that keypair. The certificate will contain a list of DNS names
and/or IP addresses from the command line flags. The key and certificate are
placed in a new directory whose name is chosen as the first domain name from
the certificate, or the first IP address if no domain names are present. It
will not overwrite existing keys or certificates.

The certificate will have a validity of 90 years.

`)
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) > 0 {
		fmt.Printf("Extra arguments: %s (maybe there are spaces in your domain list?)\n", flag.Args())
		os.Exit(1)
	}
	var domainSlice []string
	var ipSlice []string
	if *rootCAOnly {
		if *domains != "" || *ipAddresses != "" {
			flag.Usage()
			fmt.Println("\ndomains and ip-addresses are not compatible with rootCAonly option")
			os.Exit(2)
		}
	} else {
		if *domains == "" && *ipAddresses == "" {
			flag.Usage()
			fmt.Println("\nPlease provide domains or IP addresses")
			os.Exit(1)
		}

		domainSlice = split(*domains)
		domainRe := regexp.MustCompile("^[A-Za-z0-9.*-]+$")
		for _, d := range domainSlice {
			if !domainRe.MatchString(d) {
				fmt.Printf("Invalid domain name %q\n", d)
				os.Exit(1)
			}
		}
		ipSlice = split(*ipAddresses)
		for _, ip := range ipSlice {
			if net.ParseIP(ip) == nil {
				fmt.Printf("Invalid IP address %q\n", ip)
				os.Exit(1)
			}
		}
	}

	acOpts := autoCreateOpts{
		namePrefix: caNamePrefix,
		createOnly: *rootCAOnly,
	}
	if *disableAutoCreate {
		acOpts.mode = noAutoCreate
		warnAboutUselessCreateOpts(&acOpts, "auto-creation is off")
	} else if *encryptCAKey {
		acOpts.mode = createAndEncrypt
	}
	issuer, err := getIssuer(*caKey, *caCert, acOpts)
	if err != nil {
		return err
	}
	if *rootCAOnly {
		return nil
	}
	_, err = sign(issuer, domainSlice, ipSlice)
	return err
}

func warnAboutUselessCreateOpts(opts *autoCreateOpts, reason string) {
	if opts.mode == createAndEncrypt {
		fmt.Printf("WARNING: encryption requested while %s. Flag will be ignored\n", reason)
	}
	if opts.namePrefix != nil && *opts.namePrefix != defaultCaNamePrefix {
		fmt.Printf("WARNING: ca-name provided while %s. Flag will be ignored\n", reason)
		opts.namePrefix = nil
	}
}
