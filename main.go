package main

import (
	"fmt"
	"net/http"

	"github.com/proudcat/tls-client-experiment/client"
	"github.com/proudcat/tls-client-experiment/types"
)

func main() {
	//TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	//TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	// host := "www.ssllabs.com"
	host := "www.linkedin.com"
	// host := "cloudflare.com"

	https_client := client.NewHTTPSClient(host, types.PROTOCOL_VERSION_TLS12)
	err := https_client.Request(http.MethodGet, "/", nil) // "GET / HTTP/1.1"

	if err != nil {
		fmt.Println("request error", err)
		return
	}
}
