package main

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/client"
	"github.com/proudcat/tls-client-experiment/types"
)

func main() {
	// host := "www.ssllabs.com"
	host := "www.linkedin.com"
	// host := "cloudflare.com"

	https_client := client.NewHTTPSClient(host, types.PROTOCOL_VERSION_TLS12)
	err := https_client.Request("GET", "/", nil)

	if err != nil {
		fmt.Println("request error", err)
		return
	}
}
