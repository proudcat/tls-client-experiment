package net

import (
	"fmt"
	"io"
	"net"

	"github.com/proudcat/tls-client-experiment/common"
)

type TCPClient struct {
	// io.Reader
	// io.Writer
	io.Closer
	conn         *net.TCPConn
	in_bound_buf *common.Buffer
}

func DialTCP(endpoint string) (*TCPClient, error) {

	fmt.Printf("connecting with %s\n", endpoint)

	addr, err := net.ResolveTCPAddr("tcp", endpoint)
	if err != nil {
		return nil, err
	}

	fmt.Printf("resolved IP address : %s\n", addr)

	conn, err := net.DialTCP("tcp", nil, addr)

	if err != nil {
		return nil, err
	}

	fmt.Println("connected")

	client := &TCPClient{
		in_bound_buf: common.NewBuffer(),
		conn:         conn,
	}
	return client, err
}

func (c TCPClient) Close() error {
	return c.conn.Close()
}

func (c TCPClient) Size() int {
	return c.in_bound_buf.Size()
}

func (c TCPClient) Write(data []byte) error {
	fmt.Printf(">>>>> sending %d bytes\n", len(data))
	_, err := c.conn.Write(data)
	if err != nil {
		fmt.Println("sending failed:", err.Error())
	}
	return err
}

func (c *TCPClient) Read(n int) ([]byte, error) {

	fmt.Println("Reading response ", n)
	fmt.Println("Buffer size ", c.in_bound_buf.Size())

	if c.in_bound_buf.Size() < n {
		chunk := make([]byte, n)
		// using io.ReadFull to block Read until whole data is sent from server (https://stackoverflow.com/questions/26999615/go-tcp-read-is-non-blocking)
		_, err := io.ReadFull(c.conn, chunk)
		if err != nil {
			return nil, err
		}
		c.in_bound_buf.Write(chunk)
	}

	out, err := c.in_bound_buf.ReadBytes(n)

	if err != nil {
		return nil, err
	}

	return out, nil
}
