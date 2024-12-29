package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/coreUtils"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/message"
	"github.com/proudcat/tls-client-experiment/model"
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
	cipherSuite     constants.CipherSuiteInfo
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

func (c *TLSClient) Handshake() error {

	//sending client hello
	clientHello := message.MakeClientHello(c.version, c.host)
	c.securityParams.ClientRandom = clientHello.ClientRandom
	clientHelloPayload := clientHello.GetClientHelloPayload()
	c.messages.Write(helpers.IgnoreRecordHeader(clientHelloPayload))

	fmt.Println(clientHello)
	if err := c.Write(clientHelloPayload); err != nil {
		return nil
	}

	c.readServerResponse()
	return nil
}

func (client *TLSClient) Write(data []byte) error {
	fmt.Printf("Writing %d bytes to server\n", len(data))

	err := client.tcp.Write(data)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return err
	}
	return err
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

	client.cipherSuite = *constants.GCipherSuites.GetSuiteInfoForByteCode(serverHello.CipherSuite)
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

// import (
// 	"encoding/binary"
// 	"fmt"

// 	"github.com/proudcat/tls-client-experiment/common"
// 	"github.com/proudcat/tls-client-experiment/cryptoHelpers"
// 	"github.com/proudcat/tls-client-experiment/model"
// 	"github.com/proudcat/tls-client-experiment/record"
// )

// type TLSClient struct {
// 	tls        uint16
// 	host       string
// 	tcp        *TcpClient
// 	client_seq byte
// 	server_seq byte
// 	hs_params  *model.SecurityParameters
// 	messages   *common.Buffer
// }

// func NewTLSClient(host string, tls uint16) (*TLSClient, error) {

// 	tcp_client, err := NewTcpClient(host)

// 	if err != nil {
// 		return nil, err
// 	}

// 	client := &TLSClient{
// 		tls:        tls,
// 		host:       host,
// 		tcp:        tcp_client,
// 		client_seq: 0,
// 		server_seq: 0,
// 		hs_params:  &model.SecurityParameters{},
// 		messages:   common.NewBuffer(),
// 	}

// 	return client, nil
// }

// func (c TLSClient) Close() {
// 	c.tcp.Close()
// }

// func (c *TLSClient) ReadRecord() ([]byte, error) {

// 	header_bytes, err := c.tcp.Read(record.RECORD_HEADER_SIZE)

// 	if err != nil {
// 		return nil, fmt.Errorf("could not read record header: %v", err)
// 	}

// 	body_size := int(binary.BigEndian.Uint16(header_bytes[3:5]))

// 	body_bytes, err := c.tcp.Read(body_size)

// 	if err != nil {
// 		return nil, fmt.Errorf("could not read record body: %v", err)
// 	}

// 	chunk := append(header_bytes, body_bytes...)

// 	return chunk, nil
// }

// func (c *TLSClient) Handshake() error {

// 	/*********** send client_hello ***********/
// 	client_hello := record.NewClientHelloRecord(c.tls, c.host)
// 	c.hs_params.ClientRandom = client_hello.Message.ClientRandom
// 	client_hello_bytes := client_hello.ToBytes()
// 	err := c.tcp.Send(client_hello_bytes)
// 	c.messages.Write(client_hello_bytes[5:])
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("Client Hello:", client_hello)

// 	recv_buf := common.NewBuffer()

// 	/*********** receive server_hello ***********/
// 	server_hello_bytes, err := c.ReadRecord()
// 	if err != nil {
// 		return err
// 	}
// 	recv_buf.Write(server_hello_bytes)

// 	c.messages.Write(server_hello_bytes[5:])
// 	server_hello := &record.ServerHelloRecord{}
// 	if err := server_hello.FromBuffer(recv_buf); err != nil {
// 		return err
// 	}
// 	c.hs_params.CipherSuite = server_hello.Message.CipherSuite
// 	c.hs_params.ServerRandom = server_hello.Message.ServerRandom

// 	fmt.Println("Server Hello:", server_hello)

// 	/*********** receive server certificate ***********/
// 	if recv_buf.Size() > 0 {
// 		// multiple message handshake which means there are multiple handshakes in on record.
// 		// |record Header| Server Hello | Certificate |...|
// 		// we should prepend record header for Certificate Handshake
// 		header_prepended_buf := common.NewBuffer()
// 		header_prepended_buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00}) // prepend record header
// 		header_prepended_buf.Write(recv_buf.Drain())
// 		recv_buf.Write(header_prepended_buf.PeekAllBytes())
// 	} else {
// 		server_certificate_bytes, err := c.ReadRecord()
// 		if err != nil {
// 			return err
// 		}
// 		c.messages.Write(server_certificate_bytes[5:])
// 		recv_buf.Write(server_certificate_bytes)
// 	}
// 	server_certificate := &record.ServerCertificateRecord{}
// 	server_certificate.FromBuffer(recv_buf)
// 	fmt.Println("Server Certificate:", server_certificate)

// 	roots, err := record.LoadTrustStore()
// 	if err != nil {
// 		return err
// 	}

// 	if valid := server_certificate.Verify(roots, c.host); !valid {
// 		return fmt.Errorf("bad certificate chain")
// 	}

// 	/*********** receive server certificate status ***********/
// 	support_status_request := server_hello.SupportExtension(common.EXT_TYPE_STATUS_REQUEST)
// 	if support_status_request {
// 		if recv_buf.Size() > 0 {
// 			//multiple message handshake
// 			header_prepended_buf := common.NewBuffer()
// 			header_prepended_buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
// 			header_prepended_buf.Write(recv_buf.Drain())
// 			recv_buf.Write(header_prepended_buf.PeekAllBytes())
// 		} else {
// 			recv_bytes, err := c.ReadRecord()
// 			if err != nil {
// 				return err
// 			}
// 			c.messages.Write(recv_bytes[5:])
// 			recv_buf.Write(recv_bytes)
// 		}
// 		server_certificate_status := &record.ServerCertificateStatusRecord{}
// 		server_certificate_status.FromBuffer(recv_buf)
// 		fmt.Println("Server Certificate Status:", server_certificate_status)
// 	}

// 	/*********** receive server_key_exchange ***********/
// 	if recv_buf.Size() > 0 {
// 		//multiple message handshake
// 		header_prepended_buf := common.NewBuffer()
// 		header_prepended_buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
// 		header_prepended_buf.Write(recv_buf.Drain())
// 		recv_buf.Write(header_prepended_buf.PeekAllBytes())
// 	} else {
// 		recv_bytes, err := c.ReadRecord()
// 		if err != nil {
// 			return err
// 		}
// 		c.messages.Write(recv_bytes[5:])
// 		recv_buf.Write(recv_bytes)
// 	}
// 	server_key_exchange := &record.ServerKeyExchangeRecord{}
// 	server_key_exchange.FromBuffer(recv_buf)
// 	fmt.Println("Server Key Exchange:", server_key_exchange)

// 	c.hs_params.ServerKeyExchangePublicKey = server_key_exchange.PublicKey
// 	c.hs_params.Curve = common.GCurves.GetCurveInfoForByteCode(server_key_exchange.CurveID).Curve

// 	if !server_key_exchange.VerifySignature(c.hs_params, server_certificate.Certificates[0].Certificate.PublicKey) {
// 		return fmt.Errorf("could not verify signature")
// 	}

// 	/*********** receive server hello done ***********/
// 	server_hello_done := &record.ServerHelloDoneRecord{}
// 	if recv_buf.Size() > 0 {
// 		//multiple message handshake
// 		server_hello_done_buf := common.NewBuffer()
// 		server_hello_done_buf.Write([]byte{0x16, 0x03, 0x03, 0x00, 0x00})
// 		server_hello_done_buf.Write(recv_buf.Drain())
// 		recv_buf.Write(server_hello_done_buf.PeekAllBytes())
// 	} else {
// 		recv_bytes, err := c.ReadRecord()
// 		if err != nil {
// 			return err
// 		}
// 		c.messages.Write(recv_bytes[5:])
// 		recv_buf.Write(recv_bytes)
// 	}
// 	server_hello_done.FromBuffer(recv_buf)
// 	fmt.Println("Server Hello Done:", server_hello_done)

// 	if recv_buf.Size() > 0 {
// 		return fmt.Errorf("unexpected data recv_buf should be empty. size: %d", recv_buf.Size())
// 	}

// 	/*********** client key exchange ***********/
// 	client_key_exchange_record := record.NewClientKeyExchangeRecord(c.tls, c.hs_params.Curve)
// 	c.hs_params.ClientKeyExchangePrivateKey = client_key_exchange_record.PrivateKey
// 	c.messages.Write(client_key_exchange_record.ToBytes()[5:])

// 	/*********** client change cipher spec ***********/
// 	client_change_cipher_spec_record := record.NewClientChangeCipherSpecRecord(c.tls)

// 	/*********** client finished ***********/
// 	hash_messages := cryptoHelpers.HashByteArray(model.CipherSuites[c.hs_params.CipherSuite].HashingAlgorithm, c.messages.PeekAllBytes())
// 	verify_data := cryptoHelpers.MakeClientVerifyData(c.hs_params, hash_messages)
// 	if verify_data == nil {
// 		return fmt.Errorf("could not create VerifyData")
// 	}
// 	client_finished_record, err := record.MakeClientFinishedRecord(c.hs_params, verify_data, c.tls, c.client_seq)
// 	if err != nil {
// 		return err
// 	}
// 	c.client_seq += 1

// 	client_final_payload := append(client_key_exchange_record.ToBytes(), client_change_cipher_spec_record.ToBytes()...)
// 	client_final_payload = append(client_final_payload, client_finished_record.ToBytes()...)

// 	c.messages.Write(client_finished_record.HandshakeHeader.ToBytes())
// 	c.messages.Write(verify_data)

// 	err = c.tcp.Send(client_final_payload)

// 	if err != nil {
// 		return err
// 	}

// 	//receive server session ticket
// 	support_ticket := server_hello.SupportExtension(common.EXT_TYPE_SESSION_TICKET)
// 	if support_ticket {
// 		recv_bytes, err := c.ReadRecord()
// 		if err != nil {
// 			return err
// 		}
// 		server_session_ticket := &record.ServerSessionTicketRecord{}
// 		recv_buf.Write(recv_bytes)
// 		if err := server_session_ticket.FromBuffer(recv_buf); err != nil {
// 			return err
// 		}
// 		c.messages.Write(recv_bytes[5:])
// 		fmt.Println("Server Session Ticket:", server_session_ticket)
// 	}

// 	//receive server change cipher spec
// 	server_change_cipher_spec_bytes, err := c.ReadRecord()
// 	fmt.Printf("Server Change Cipher Spec: %2x", server_change_cipher_spec_bytes)
// 	if err != nil {
// 		return err
// 	}
// 	recv_buf.Write(server_change_cipher_spec_bytes)
// 	server_change_cipher_spec := &record.ServerChangeCipherSpecRecord{}
// 	if err := server_change_cipher_spec.FromBuffer(recv_buf); err != nil {
// 		return nil
// 	}

// 	//receive server finished
// 	server_finished_bytes, err := c.ReadRecord()
// 	if err != nil {
// 		return err
// 	}
// 	recv_buf.Write(server_finished_bytes)
// 	server_finished := &record.ServerFinishedRecord{}
// 	if err := server_finished.FromBuffer(c.hs_params.ServerKey, c.hs_params.ServerIV, recv_buf); err != nil {
// 		return err
// 	}
// 	c.server_seq += 1

// 	fmt.Println("Server Finished:", server_finished)

// 	return nil
// }

// func (c *TLSClient) SendAppData(data []byte) error {
// 	return nil
// }

// func (c *TLSClient) Get(path string, headers map[string]string) error {

// 	out := fmt.Sprintln("GET ", path, " HTTP/1.1")
// 	out += fmt.Sprintln("host: ", c.host)
// 	out += fmt.Sprintln("accept: */*")
// 	// out += fmt.Sprintln("accept-language: en,zh-CN;q=0.9,zh;q=0.8")
// 	// out += fmt.Sprintln("authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1UaEVOVUpHTkVNMVFURTRNMEZCTWpkQ05UZzVNRFUxUlRVd1FVSkRNRU13UmtGRVFrRXpSZyJ9.eyJwd2RfYXV0aF90aW1lIjoxNzMyNzc2NzM0OTA3LCJzZXNzaW9uX2lkIjoibVQ5a0E2SjBmbkVjSGQwd3V2S2ZuR2tFZmNjMTNrVkEiLCJodHRwczovL2FwaS5vcGVuYWkuY29tL3Byb2ZpbGUiOnsiZW1haWwiOiJrb2FsYXlsakBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0sImh0dHBzOi8vYXBpLm9wZW5haS5jb20vYXV0aCI6eyJwb2lkIjoib3JnLTNLM3JzVmhhT2c1WXBYdUNNdlUxdnRRNSIsInVzZXJfaWQiOiJ1c2VyLWNLc3Fld2twR0pLNUduYzFpVjJnN2tYdiJ9LCJpc3MiOiJodHRwczovL2F1dGgwLm9wZW5haS5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTM0NTc4MTYzNzExNzkzNDcwMzgiLCJhdWQiOlsiaHR0cHM6Ly9hcGkub3BlbmFpLmNvbS92MSIsImh0dHBzOi8vb3BlbmFpLm9wZW5haS5hdXRoMGFwcC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNzMyNzc2NzM2LCJleHAiOjE3MzM2NDA3MzYsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwgbW9kZWwucmVhZCBtb2RlbC5yZXF1ZXN0IG9yZ2FuaXphdGlvbi5yZWFkIG9yZ2FuaXphdGlvbi53cml0ZSBvZmZsaW5lX2FjY2VzcyIsImF6cCI6IlRkSkljYmUxNldvVEh0Tjk1bnl5d2g1RTR5T282SXRHIn0.ICESTB5cS0B15Z6HO4AcY6co4s2jXfcgZPIpmt5ZZwHsC5vn4SPLwgYWAh_x6fr6_CMzuZ3Wz3uZSFqcE5_Ggv-VjqX2HUDFvcImnQp_-1-D2i7khxUIKCi0_IbH0EUQoGg969p4pa7jw3aXmcAtDWnXFgqnP0SqcwPXfsWdX85l19t7et5zP8NpGB5_2X3WQ63JXSqiL-FQllmqtqgrXrs3P5ebbAExW-5rnUcUVhWVIZZzBYVZr2eW2vAdqnYmjKgizQwVbqM-3Y9CetHwr3Cp_tMofJWUPtFjMW9QjMk6KC_TBTIkFVBUoBQE0HMGDkODlTB5Nk_XYn9W_kptqA")
// 	// out += fmt.Sprintln("user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
// 	// out += fmt.Sprintln("pragma: no-cache")
// 	// out += fmt.Sprintln("priority: u=1, i")
// 	// out += fmt.Sprintln("referer: https://" + c.host + "/")
// 	// out += fmt.Sprintln("sec-ch-ua: \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"")
// 	// out += fmt.Sprintln("sec-fetch-mode: cors")
// 	// out += fmt.Sprintln("sec-fetch-site: same-origin")

// 	out += "\r\n"

// 	fmt.Println(out)

// 	if err := c.Handshake(); err != nil {
// 		fmt.Println("handshake failed", err)
// 	}

// 	appData, err := record.NewAppData(c.hs_params.ClientKey, c.hs_params.ClientIV, []byte(out), c.tls, c.client_seq)

// 	if err != nil {
// 		return err
// 	}

// 	//send app data
// 	if err := c.tcp.Send(appData.ToBytes()); err != nil {
// 		return err
// 	}

// 	//receive app data
// 	app_data_bytes, err := c.ReadRecord()
// 	buf := common.NewBuffer()
// 	buf.Write(app_data_bytes)
// 	if err != nil {
// 		return err
// 	}
// 	app_data := &record.ApplicationData{}
// 	if err := app_data.FromBuffer(buf, c.hs_params.ServerKey, c.hs_params.ServerIV, c.server_seq); err != nil {
// 		return err
// 	}
// 	if app_data.RecordHeader.ContentType != common.RecordApplicationData {
// 		return fmt.Errorf("unexpected content type")
// 	}
// 	c.server_seq += 1

// 	fmt.Println("App Data:", string(app_data.Data))

// 	return nil
// }
