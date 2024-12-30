package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/cryptoHelpers"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/message"
	"github.com/proudcat/tls-client-experiment/types"
)

/*

   Client                                               Server

   ClientHello                  -------->
                                                   ServerHello
                                                   Certificate
                                             ServerKeyExchange
                                <--------      ServerHelloDone
   ClientKeyExchange
   ChangeCipherSpec
   Finished                     -------->
                                              ChangeCipherSpec
                                <--------             Finished
   Application Data             <------->     Application Data

   				TLS1.2 Handshake workflow
*/

type TLSClient struct {
	io.Closer
	version         uint16
	host            string
	tcp             *TCPClient
	messages        *common.Buffer
	clientSeqNumber byte
	serverSeqNumber byte
	cipherSuite     uint16
	securityParams  types.SecurityParameters
}

func NewTLSClient(host string, version uint16) *TLSClient {
	tcp, err := DialTCP(host + ":443")
	if err != nil {
		fmt.Println("DialTCP failed:", err.Error())
		os.Exit(1)
	}

	tlsClient := TLSClient{
		version:         version,
		host:            host,
		tcp:             tcp,
		messages:        common.NewBuffer(),
		clientSeqNumber: 0,
		serverSeqNumber: 0,
	}

	return &tlsClient
}

func (client *TLSClient) Close() error {
	err := client.tcp.Close()
	return err
}

func (c *TLSClient) Write(data []byte) error {
	err := c.tcp.Write(data)
	if err != nil {
		return err
	}
	return err
}

func (c *TLSClient) ReadRecord() ([]byte, error) {

	header_bytes, err := c.tcp.Read(types.RECORD_HEADER_SIZE)

	if err != nil {
		return nil, err
	}

	body_size := int(binary.BigEndian.Uint16(header_bytes[3:5]))

	body_bytes, err := c.tcp.Read(body_size)

	if err != nil {
		return nil, err
	}

	chunk := append(header_bytes, body_bytes...)

	record_type := header_bytes[0]
	if record_type == types.RECORD_TYPE_ALERT {
		fmt.Println("Alert:", types.AlertError(body_bytes[0]).Error(), chunk)
		return nil, errors.New(types.AlertError(body_bytes[0]).Error())
	}

	return chunk, nil
}

func (c *TLSClient) Handshake() error {

	/*********** send client hello ***********/
	client_hello_record := message.NewClientHello(c.version, c.host)
	c.securityParams.ClientRandom = client_hello_record.Message.Random
	client_hello_bytes := client_hello_record.ToBytes()
	c.messages.Write(client_hello_bytes[5:])
	fmt.Println(client_hello_record)
	if err := c.Write(client_hello_bytes); err != nil {
		return nil
	}

	/*********** receive server hello ***********/
	server_hello_bytes, err := c.ReadRecord()
	if err != nil {
		return err
	}

	recv_buf := common.NewBuffer()
	recv_buf.Write(server_hello_bytes)
	server_hello := message.ServerHello{}
	server_hello.FromBuffer(recv_buf)
	c.securityParams.ServerRandom = server_hello.Message.Random
	c.cipherSuite = server_hello.Message.CipherSuite
	c.messages.Write(server_hello_bytes[5:])
	fmt.Println(server_hello)

	/*********** receive server certificate ***********/
	if recv_buf.Size() > 0 {
		// multiple message handshake which means there are multiple handshakes in on record.
		// |record Header| Server Hello | Certificate |...|
		// we should prepend record header for Certificate Handshake
		buf := common.NewBuffer()
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00}) // prepend record header
		buf.Write(recv_buf.Drain())
		recv_buf.Write(buf.PeekAllBytes())
	} else {
		server_certificate_bytes, err := c.ReadRecord()
		if err != nil {
			return err
		}
		c.messages.Write(server_certificate_bytes[5:])
		recv_buf.Write(server_certificate_bytes)
	}
	server_certificate := &message.ServerCertificate{}
	server_certificate.FromBuffer(recv_buf)
	fmt.Println(server_certificate)

	roots, err := common.LoadTrustStore()
	if err != nil {
		return err
	}

	if valid := server_certificate.Verify(roots, c.host); !valid {
		return fmt.Errorf("bad certificate chain")
	}

	/*********** receive server certificate status ***********/
	support_status_request := server_hello.SupportExtension(types.EXT_TYPE_STATUS_REQUEST)
	fmt.Println("support status request:", support_status_request)
	if support_status_request {
		if recv_buf.Size() > 0 {
			//multiple message handshake
			buf := common.NewBuffer()
			buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
			buf.Write(recv_buf.Drain())
			recv_buf.Write(buf.PeekAllBytes())
		} else {
			recv_bytes, err := c.ReadRecord()
			if err != nil {
				return err
			}
			c.messages.Write(recv_bytes[5:])
			recv_buf.Write(recv_bytes)
		}
		server_certificate_status := &message.ServerCertificateStatus{}
		server_certificate_status.FromBuffer(recv_buf)
		fmt.Println(server_certificate_status)
	}

	/*********** receive server_key_exchange ***********/
	if recv_buf.Size() > 0 {
		//multiple message handshake
		buf := common.NewBuffer()
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
		buf.Write(recv_buf.Drain())
		recv_buf.Write(buf.PeekAllBytes())
	} else {
		recv_bytes, err := c.ReadRecord()
		if err != nil {
			return err
		}
		c.messages.Write(recv_bytes[5:])
		recv_buf.Write(recv_bytes)
	}
	server_key_exchange := message.ServerKeyExchange{}
	server_key_exchange.FromBuffer(recv_buf)
	fmt.Println(server_key_exchange)

	c.securityParams.ServerKeyExchangePublicKey = server_key_exchange.PublicKey
	c.securityParams.Curve = types.Curves[server_key_exchange.CurveID].Curve

	if !server_key_exchange.VerifySignature(c.securityParams, server_certificate.Certificates[0].Certificate.PublicKey) {
		return fmt.Errorf("could not verify signature")
	} else {
		fmt.Println("Signature verified!")
	}

	/*********** receive server hello done ***********/
	server_hello_done := message.ServerHelloDone{}
	if recv_buf.Size() > 0 {
		//multiple message handshake
		buf := common.NewBuffer()
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
		buf.Write(recv_buf.Drain())
		recv_buf.Write(buf.PeekAllBytes())
	} else {
		recv_bytes, err := c.ReadRecord()
		if err != nil {
			return err
		}
		c.messages.Write(recv_bytes[5:])
		recv_buf.Write(recv_bytes)
	}
	server_hello_done.FromBuffer(recv_buf)
	fmt.Println(server_hello_done)

	if recv_buf.Size() > 0 {
		return fmt.Errorf("unexpected data recv_buf should be empty. size: %d", recv_buf.Size())
	}

	/*********** client key exchange ***********/
	client_key_exchange := message.NewClientKeyExchange(c.version, c.securityParams.Curve)
	c.securityParams.ClientKeyExchangePrivateKey = client_key_exchange.PrivateKey
	c.messages.Write(client_key_exchange.ToBytes()[5:])
	fmt.Println(client_key_exchange)

	/*********** client change cipher spec ***********/
	client_change_cipher_spec := message.NewClientChangeCipherSpec(c.version)
	fmt.Println(client_change_cipher_spec)

	/*********** client finished ***********/
	hash_messages := helpers.HashByteArray(types.CipherSuites[c.cipherSuite].HashingAlgorithm, c.messages.PeekAllBytes())
	verify_data := cryptoHelpers.MakeClientVerifyData(&c.securityParams, hash_messages)
	if verify_data == nil {
		return fmt.Errorf("could not create VerifyData")
	}
	client_finished, err := message.MakeClientFinished(&c.securityParams, verify_data, c.version, c.clientSeqNumber)
	if err != nil {
		return err
	}
	c.clientSeqNumber += 1

	client_final_payload := append(client_key_exchange.ToBytes(), client_change_cipher_spec.ToBytes()...)
	client_final_payload = append(client_final_payload, client_finished.ToBytes()...)

	c.messages.Write(client_finished.HandshakeHeader.ToBytes())
	c.messages.Write(verify_data)
	fmt.Println(client_finished)

	if err := c.Write(client_final_payload); err != nil {
		return err
	}

	return nil
}

func (client *TLSClient) Read() ([]byte, error) {
	fmt.Println("Reading response")

	header_bytes, err := client.tcp.Read(5)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		// client.Close()
		// os.Exit(1)
		return nil, err
	}

	body_size := int(binary.BigEndian.Uint16(header_bytes[3:5]))

	body_bytes, err := client.tcp.Read(body_size)

	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return nil, err
	}

	record := append(header_bytes, body_bytes...)

	fmt.Printf("Message received from server: %x\n", record)
	return record, nil
}
