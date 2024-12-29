package main

import (
	core "github.com/proudcat/tls-client-experiment/cmd"
)

func main() {
	//TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	//TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	host := "www.ssllabs.com"

	client := core.MakeTLSClient(host, "TLS 1.2")
	client.Execute("GET / HTTP/1.1")
	client.Terminate()
}
