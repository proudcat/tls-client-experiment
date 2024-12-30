package common

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

func Random32() [32]byte {
	r := make([]byte, 32)
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}
	var tmp [32]byte
	copy(tmp[:], r)
	return tmp
}

func LoadTrustStore() (roots *x509.CertPool, err error) {
	pem_bytes := []byte(TRUST_STORE)
	roots = x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pem_bytes)
	if !ok {
		fmt.Println("failed to parse root certificate", err)
		return nil, fmt.Errorf("failed to parse root certificate")
	}
	return
}
