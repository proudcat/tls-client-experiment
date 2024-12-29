package client

import "io"

type HTTPSClient struct {
	io.Closer
	tls *TLSClient
}

func NewHTTPSClient(host string, tls_version uint16) *HTTPSClient {

	tls := NewTLSClient(host, tls_version)

	return &HTTPSClient{
		tls: tls,
	}
}

func (client *HTTPSClient) Request(method, path string, headers map[string]string) error {
	if err := client.tls.Handshake(); err != nil {
		return err
	}

	return client.tls.Close()
}
