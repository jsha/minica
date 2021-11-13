package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/jsha/minica/certutils"
)

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
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
	if len(flag.Args()) > 0 {
		fmt.Printf("Extra arguments: %s (maybe there are spaces in your domain list?)\n", flag.Args())
		os.Exit(1)
	}
	domainSlice := split(*domains)
	domainRe := regexp.MustCompile("^[A-Za-z0-9.*-]+$")
	for _, d := range domainSlice {
		if !domainRe.MatchString(d) {
			fmt.Printf("Invalid domain name %q\n", d)
			os.Exit(1)
		}
	}
	ipSlice := split(*ipAddresses)
	for _, ip := range ipSlice {
		if net.ParseIP(ip) == nil {
			fmt.Printf("Invalid IP address %q\n", ip)
			os.Exit(1)
		}
	}
	issuer, err := certutils.GetIssuer(*caKey, *caCert)
	if err != nil {
		return err
	}
	_, err = certutils.Sign(issuer, domainSlice, ipSlice)
	return err
}
