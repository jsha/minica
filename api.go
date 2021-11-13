package main

import (
	"C"

	"github.com/jsha/minica/certutils"
)

//export generateCertificate
func generateCertificate(domain *C.char) C.int {
	iss, err := certutils.GetIssuer("minica-key.pem", "minica.pem")
	if err != nil {
		return 1
	}
	_, err = certutils.Sign(iss, []string{C.GoString(domain)}, []string{})
	if err != nil {
		return 2
	}
	return 0
}
