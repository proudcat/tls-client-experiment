package http

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

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

	URL *url.URL

	Proto string // "HTTP/1.0"

	// if the request is a client request, the header will include
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
	// HTTP defines that header names are case-insensitive. The
	// request parser implements this by using CanonicalHeaderKey,
	// making the first character and any characters following a
	// hyphen uppercase and the rest lowercase.
	Header http.Header

	// Body is the request's body.
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
