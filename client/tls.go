package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/coreUtils"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/message"
	"github.com/proudcat/tls-client-experiment/model"
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
	securityParams  coreUtils.SecurityParams
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

	/*********** send client_hello ***********/
	client_hello_record := message.NewClientHello(c.version, c.host)
	c.securityParams.ClientRandom = client_hello_record.Message.Random
	client_hello_bytes := client_hello_record.ToBytes()
	c.messages.Write(helpers.IgnoreRecordHeader(client_hello_bytes))
	fmt.Println(client_hello_record)
	if err := c.Write(client_hello_bytes); err != nil {
		return nil
	}

	/*********** receive server_hello ***********/
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
	c.messages.Write(helpers.IgnoreRecordHeader(server_hello_bytes))
	fmt.Println(server_hello)

	// c.readServerResponse()
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

func (client *TLSClient) readServerResponse() {
	var answer []byte
	isMultipleHandshakeMessages := false

	answer, err := client.Read()
	if err != nil {
		fmt.Println(err)
		client.Close()
		os.Exit(1)
	}
	serverHello, left_answer, err := model.ParseServerHello(answer)
	if err != nil {
		fmt.Println(err)
		client.Close()
		os.Exit(1)
	}
	fmt.Println("Support Ticket:", serverHello.SupportTicket())

	client.cipherSuite = binary.BigEndian.Uint16(serverHello.CipherSuite[:])
	client.securityParams.ServerRandom = serverHello.ServerRandom
	client.messages.Write(helpers.IgnoreRecordHeader(answer))

	fmt.Println(serverHello)
	//check is multiple handshake messages
	if len(left_answer) == 0 {
		answer, err = client.Read()
		if err != nil {
			fmt.Println(err)
			client.Close()
			os.Exit(1)
		}
	} else {
		isMultipleHandshakeMessages = true
		//prepend record header for the rest handshakes
		restRecordBodyLength := helpers.ConvertIntToByteArray(uint16(len(left_answer)))
		serverCertificateRecordHeader := append([]byte{0x16, 0x03, 0x03}, restRecordBodyLength[:]...)
		left_answer = append(serverCertificateRecordHeader, left_answer...)
		answer = left_answer
	}

	serverCertificate, left_answer, err := model.ParseServerCertificate(answer)
	if err != nil {
		fmt.Println(err)
		client.Close()
		os.Exit(1)
	}

	roots, err := model.LoadTrustStore()
	if err != nil {
		panic(err)
	}

	validCert := serverCertificate.Verify(roots, client.host)

	if !validCert {
		panic("bad certificate chain")
	}

	if !isMultipleHandshakeMessages {
		client.messages.Write(helpers.IgnoreRecordHeader(answer))
	}

	fmt.Println(serverCertificate)
	//check is multiple handshake messages
	if len(left_answer) == 0 {
		isMultipleHandshakeMessages = false
		answer, err = client.Read()
		if err != nil {
			fmt.Println(err)
			client.Close()
			os.Exit(1)
		}
	} else {
		isMultipleHandshakeMessages = true
		restRecordBodyLength := helpers.ConvertIntToByteArray(uint16(len(left_answer)))
		serverKeyExchangeRecordHeader := append([]byte{0x16, 0x03, 0x03}, restRecordBodyLength[:]...)
		left_answer = append(serverKeyExchangeRecordHeader, left_answer...)
		answer = left_answer
	}

	serverKeyExchange, left_answer, err := model.ParseServerKeyExchange(answer)
	if err != nil {
		fmt.Println(err)
	} else {
		if !isMultipleHandshakeMessages {
			client.messages.Write(helpers.IgnoreRecordHeader(answer))
		}

		fmt.Println(serverKeyExchange)

		//check is multiple handshake messages
		if len(left_answer) == 0 {
			isMultipleHandshakeMessages = false
			answer, err = client.Read()
			if err != nil {
				fmt.Println(err)
				client.Close()
				os.Exit(1)
			}
		} else {
			isMultipleHandshakeMessages = true
			restRecordBodyLength := helpers.ConvertIntToByteArray(uint16(len(left_answer)))
			serverHelloDoneRecordHeader := append([]byte{0x16, 0x03, 0x03}, restRecordBodyLength[:]...)
			left_answer = append(serverHelloDoneRecordHeader, left_answer...)
			answer = left_answer
		}
	}
	client.securityParams.ServerKeyExchangePublicKey = serverKeyExchange.PublicKey
	client.securityParams.Curve = constants.GCurves.GetCurveInfoForByteCode(serverKeyExchange.CurveID).Curve

	if !serverKeyExchange.VerifySignature(&client.securityParams, serverCertificate.Certificates[0].Certificate.PublicKey) {
		fmt.Println("Could not verify signature!")
		client.Close()
		os.Exit(1)
	}

	serverHelloDone, left_answer, err := model.ParseServerHelloDone(answer)
	if err != nil {
		fmt.Println(err)
		client.Close()
		os.Exit(1)
	}

	if len(left_answer) != 0 {
		fmt.Println("Answer should be empty after ServerHelloDone!", len(answer), answer)
	}

	if !isMultipleHandshakeMessages {
		client.messages.Write(helpers.IgnoreRecordHeader(answer))
	}

	fmt.Println(serverHelloDone)
}
