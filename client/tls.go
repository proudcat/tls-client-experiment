package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/message"
	"github.com/proudcat/tls-client-experiment/types"
)

/*

   Client                                               Server

   ClientHello                  -------->
                                                   ServerHello
                                                   Certificate
											[CertificateStatus]
                                             ServerKeyExchange
                                <--------      ServerHelloDone
   ClientKeyExchange
   ChangeCipherSpec
   Finished                     -------->
											[NewSessionTicket]
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
	messages        common.Buffer
	clientSeqNumber byte
	serverSeqNumber byte
	cipherSuite     uint16
	securityParams  helpers.SecurityParameters
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
		messages:        common.Buffer{},
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

func (c *TLSClient) SendAppData(data []byte) error {
	msg, err := message.NewAppData(c.securityParams.ClientKey, c.securityParams.ClientIV, data, c.version, c.clientSeqNumber)
	if err != nil {
		return err
	}
	//todo check it should increment seq number
	c.clientSeqNumber += 1
	return c.Write(msg.Bytes())
}

func (c *TLSClient) RecvAppData() (*message.AppData, error) {
	recv_bytes, err := c.ReadRecord()
	if err != nil {
		return nil, err
	}

	recv_buf := &common.Buffer{}
	recv_buf.Write(recv_bytes)
	app_data := &message.AppData{}
	app_data.FromBuffer(c.securityParams.ServerKey, c.securityParams.ServerIV, c.serverSeqNumber, recv_buf)
	c.serverSeqNumber += 1

	return app_data, nil
}

func (c *TLSClient) ReadRecord() ([]byte, error) {

	header_bytes, err := c.tcp.Read(types.RECORD_HEADER_SIZE)

	if err != nil {
		return nil, err
	}

	body_size := uint32(binary.BigEndian.Uint16(header_bytes[3:5]))

	body_bytes, err := c.tcp.Read(body_size)

	if err != nil {
		return nil, err
	}

	chunk := append(header_bytes, body_bytes...)

	record_type := header_bytes[0]
	if record_type == types.RECORD_TYPE_ALERT {
		alert := message.AlertError{}
		alert.FromBytes(chunk)
		return nil, errors.New(alert.String())
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

	recv_buf := &common.Buffer{}
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
		buf := common.Buffer{}
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00}) // prepend record header
		buf.Write(recv_buf.Bytes())
		recv_buf.Write(buf.Bytes())
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
	recv_buf.Shrink()

	/*********** receive server certificate status ***********/
	support_status_request := server_hello.SupportExtension(types.EXT_TYPE_STATUS_REQUEST)
	fmt.Println("support status request:", support_status_request)
	if support_status_request {
		if recv_buf.Size() > 0 {
			//multiple message handshake
			buf := common.Buffer{}
			buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
			buf.Write(recv_buf.Bytes())
			recv_buf.Write(buf.Bytes())
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
	recv_buf.Shrink()

	/*********** receive server_key_exchange ***********/
	if recv_buf.Size() > 0 {
		//multiple message handshake
		buf := common.Buffer{}
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
		buf.Write(recv_buf.Bytes())
		recv_buf.Write(buf.Bytes())
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
	recv_buf.Shrink()

	/*********** receive server hello done ***********/
	server_hello_done := message.ServerHelloDone{}
	if recv_buf.Size() > 0 {
		//multiple message handshake
		buf := common.Buffer{}
		buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
		buf.Write(recv_buf.Bytes())
		recv_buf.Write(buf.Bytes())
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
	recv_buf.Shrink()

	/*********** client key exchange ***********/
	client_key_exchange := message.NewClientKeyExchange(c.version, c.securityParams.Curve)
	c.securityParams.ClientKeyExchangePrivateKey = client_key_exchange.PrivateKey
	c.messages.Write(client_key_exchange.ToBytes()[5:])
	fmt.Println(client_key_exchange)

	/*********** client change cipher spec ***********/
	client_change_cipher_spec := message.NewClientChangeCipherSpec(c.version)
	fmt.Println(client_change_cipher_spec)

	/*********** client finished ***********/
	hash_messages := helpers.HashByteArray(types.CipherSuites[c.cipherSuite].HashingAlgorithm, c.messages.Bytes())
	verify_data := helpers.MakeClientVerifyData(&c.securityParams, hash_messages)
	if verify_data == nil || len(verify_data) != 12 {
		return fmt.Errorf("could not create VerifyData")
	}
	client_finished, err := message.MakeClientFinished(&c.securityParams, verify_data, c.version, 0)
	if err != nil {
		return err
	}

	client_final_payload := append(client_key_exchange.ToBytes(), client_change_cipher_spec.ToBytes()...)
	client_final_payload = append(client_final_payload, client_finished.ToBytes()...)

	c.messages.Write(client_finished.HandshakeHeader.ToBytes())
	c.messages.Write(verify_data)
	fmt.Println(client_finished)
	c.clientSeqNumber += 1

	// send client key exchange || change cipher spec || finished
	if err := c.Write(client_final_payload); err != nil {
		return err
	}

	if recv_buf.Size() > 0 {
		return fmt.Errorf("unexpected data recv_buf should be empty. size: %d", recv_buf.Size())
	}

	/*********** receive server session ticket ***********/
	support_ticket := server_hello.SupportExtension(types.EXT_TYPE_SESSION_TICKET)
	fmt.Println("support ticket:", support_ticket)
	if support_ticket {
		recv_bytes, err := c.ReadRecord()
		if err != nil {
			return err
		}
		server_session_ticket := message.ServerSessionTicket{}
		recv_buf.Write(recv_bytes)
		if err := server_session_ticket.FromBuffer(recv_buf); err != nil {
			return err
		}
		c.messages.Write(recv_bytes[5:])
		fmt.Println(server_session_ticket)
	}
	recv_buf.Shrink()

	/*********** receive server change cipher spec ***********/
	server_change_cipher_spec_bytes, err := c.ReadRecord()
	if err != nil {
		return err
	}
	recv_buf.Write(server_change_cipher_spec_bytes)
	server_change_cipher_spec := message.ServerChangeCipherSpec{}
	if err := server_change_cipher_spec.FromBuffer(recv_buf); err != nil {
		return err
	}
	recv_buf.Shrink()
	fmt.Println(server_change_cipher_spec)

	/*********** receive server finished ***********/
	server_finished_bytes, err := c.ReadRecord()
	if err != nil {
		return err
	}
	recv_buf.Write(server_finished_bytes)
	server_finished := message.ServerFinished{}
	if err := server_finished.FromBuffer(c.securityParams.ServerKey, c.securityParams.ServerIV, recv_buf); err != nil {
		return err
	}
	c.serverSeqNumber += 1

	fmt.Println(server_finished)
	//todo check verify data???

	return nil
}
