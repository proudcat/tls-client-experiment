package http

import (
	"fmt"
	"testing"
)

func TestNewRequest(t *testing.T) {

	host := "www.linkin.com"
	path_with_query := "/"
	method := "GET"
	headers := map[string]string{
		"accept-encoding": "gzip, deflate",
		"Accept-Language": "en-us",
		"fOO":             "Bar",
		"foo":             "two",
	}

	uri := fmt.Sprintf("https://%s%s", host, path_with_query)

	req, err := NewRequest(method, uri, nil)

	if err != nil {
		t.FailNow()
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	fmt.Println(req)

}
