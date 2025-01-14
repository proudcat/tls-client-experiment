package http

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// NewRequest returns a new Request given a method, URL, and optional body.
func NewRequest(method, uri string, body io.ReadCloser) (*Request, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	method = strings.ToUpper(method)

	return &Request{
		Method: method,
		URL:    u,
		Proto:  "HTTP/1.0",
		Header: make(http.Header),
		Body:   body,
	}, nil
}

type Request struct {
	// Method specifies the HTTP method (GET, POST, PUT, etc.).
	// For client requests, an empty string means GET.
	Method string

	// URL specifies the URL to access (for client requests).
	// For client requests, the URL's Host specifies the server to
	// connect to, while the Request's Host field optionally
	// specifies the Host header value to send in the HTTP
	// request.
	URL *url.URL

	// The protocol version for incoming server requests.
	//
	// For client requests, these fields are ignored. The HTTP
	// client code always uses either HTTP/1.1 or HTTP/2.
	// See the docs on Transport for details.
	Proto string // "HTTP/1.0"

	// Header contains the request header fields either received
	// by the server or to be sent by the client.
	//
	// If a server received a request with header lines,
	//
	//	Host: example.com
	//	accept-encoding: gzip, deflate
	//	Accept-Language: en-us
	//	fOO: Bar
	//	foo: two
	//
	// then
	//
	//	Header = map[string][]string{
	//		"Accept-Encoding": {"gzip, deflate"},
	//		"Accept-Language": {"en-us"},
	//		"Foo": {"Bar", "two"},
	//	}
	//
	// For incoming requests, the Host header is promoted to the
	// Request.Host field and removed from the Header map.
	//
	// HTTP defines that header names are case-insensitive. The
	// request parser implements this by using CanonicalHeaderKey,
	// making the first character and any characters following a
	// hyphen uppercase and the rest lowercase.
	//
	// For client requests, certain headers such as Content-Length
	// and Connection are automatically written when needed and
	// values in Header may be ignored. See the documentation
	// for the Request.Write method.
	Header http.Header

	// Body is the request's body.
	//
	// For client requests, a nil body means the request has no
	// body, such as a GET request.
	Body io.ReadCloser
}

func (req *Request) Close() error {
	if req.Body == nil {
		return nil
	}
	return req.Body.Close()
}

func (req *Request) Write(w io.Writer) error {
	return nil
}

func (req *Request) String() string {
	out := fmt.Sprintf("%s %s %s\r\n", req.Method, req.URL.Path, req.Proto)
	req.Header.Set("Host", req.URL.Host)

	for k, v := range req.Header {
		out += fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", "))
	}
	out += "\r\n"
	return out
}

func (req Request) Bytes() []byte {
	return []byte(req.String())
}
