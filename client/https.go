package client

import (
	"fmt"
	"io"
	"strings"
)

type HTTPSClient struct {
	io.Closer
	tls  *TLSClient
	host string
}

func NewHTTPSClient(host string, tls_version uint16) *HTTPSClient {

	if len(host) == 0 {
		panic("host is empty")
	}

	host = strings.TrimSuffix(host, "/")

	tls := NewTLSClient(host, tls_version)

	return &HTTPSClient{
		tls:  tls,
		host: host,
	}
}

func (client *HTTPSClient) Get(path string, headers map[string]string) error {
	return client.Request("GET", path, headers)
}

func (client *HTTPSClient) Post(path string, headers map[string]string) error {
	return client.Request("POST", path, headers)
}

func (client *HTTPSClient) Request(method, path_with_query string, headers map[string]string) error {
	if err := client.tls.Handshake(); err != nil {
		return err
	}

	if path_with_query[0] != '/' {
		path_with_query = "/" + path_with_query
	}

	uri := fmt.Sprintf("https://%s%s", client.host, path_with_query)

	req, err := NewRequest(method, uri, nil)

	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	if err := client.tls.SendAppData(req.Bytes()); err != nil {
		return err
	}

	resp, err := client.tls.RecvAppData()

	if err != nil {
		return err
	}

	html_text := string(resp)

	fmt.Printf("\n---------------- Response ----------------\n%s", html_text)

	return client.tls.Close()
}
