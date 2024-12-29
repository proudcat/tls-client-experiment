package core

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/coreUtils"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/model"
	"github.com/proudcat/tls-client-experiment/net"
)

/*

   Client                                               Server

   ClientHello                  -------->
                                                   ServerHello
                                                  Certificate*
                                            ServerKeyExchange*
                                           CertificateRequest*
                                <--------      ServerHelloDone
   Certificate*
   ClientKeyExchange
   CertificateVerify*
   [ChangeCipherSpec]
   Finished                     -------->
                                            [ChangeCipherSpec]
                                <--------             Finished
   Application Data             <------->     Application Data

*/

type TLSClient struct {
	tlsVersion      [2]byte
	host            string
	tcp             *net.TCPClient
	messages        []byte
	clientSeqNumber byte
	serverSeqNumber byte
	cipherSuite     constants.CipherSuiteInfo
	securityParams  coreUtils.SecurityParams
}

func MakeTLSClient(host string, tlsVersion string) *TLSClient {
	tcp, err := net.DialTCP(host + ":443")
	if err != nil {
		fmt.Println("DialTCP failed:", err.Error())
		os.Exit(1)
	}

	tlsClient := TLSClient{
		tlsVersion:      constants.GTlsVersions.GetByteCodeForVersion(tlsVersion),
		host:            host,
		tcp:             tcp,
		clientSeqNumber: 0,
		serverSeqNumber: 0,
	}

	return &tlsClient
}

func (client *TLSClient) Terminate() {
	err := client.tcp.Close()
	if err != nil {
		fmt.Println(err)
	}
}

func (client *TLSClient) Execute(request string) {
	client.sendClientHello()
	client.readServerResponse()
}

func (client *TLSClient) sendToServer(payload []byte) {
	fmt.Println("Sending to server")

	err := client.tcp.Write(payload)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		client.Terminate()
		os.Exit(1)
	}
}

func (client *TLSClient) readFromServer() ([]byte, error) {
	fmt.Println("Reading response")

	header_bytes, err := client.tcp.Read(5)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		// client.Terminate()
		// os.Exit(1)
		return nil, err
	}

	body_size := int(binary.BigEndian.Uint16(header_bytes[3:5]))

	body_bytes, err := client.tcp.Read(body_size)

	record := append(header_bytes, body_bytes...)

	fmt.Printf("Message received from server: %x\n", record)
	return record, nil
}

func (client *TLSClient) sendClientHello() {

	clientHello := model.MakeClientHello(client.tlsVersion, client.host)
	client.securityParams.ClientRandom = clientHello.ClientRandom
	clientHelloPayload := clientHello.GetClientHelloPayload()
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(clientHelloPayload)...)

	fmt.Println(clientHello)
	client.sendToServer(clientHelloPayload)
}

func (client *TLSClient) readServerResponse() {
	var answer []byte
	isMultipleHandshakeMessages := false

	answer, err := client.readFromServer()
	if err != nil {
		fmt.Println(err)
		client.Terminate()
		os.Exit(1)
	}
	serverHello, left_answer, err := model.ParseServerHello(answer)
	if err != nil {
		fmt.Println(err)
		client.Terminate()
		os.Exit(1)
	}
	fmt.Println("Support Ticket:", serverHello.SupportTicket())

	client.cipherSuite = *constants.GCipherSuites.GetSuiteInfoForByteCode(serverHello.CipherSuite)
	client.securityParams.ServerRandom = serverHello.ServerRandom
	client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)

	fmt.Println(serverHello)
	//check is multiple handshake messages
	if len(left_answer) == 0 {
		answer, err = client.readFromServer()
		if err != nil {
			fmt.Println(err)
			client.Terminate()
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
		client.Terminate()
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
		client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
	}

	fmt.Println(serverCertificate)
	//check is multiple handshake messages
	if len(left_answer) == 0 {
		isMultipleHandshakeMessages = false
		answer, err = client.readFromServer()
		if err != nil {
			fmt.Println(err)
			client.Terminate()
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
			client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
		}

		fmt.Println(serverKeyExchange)

		//check is multiple handshake messages
		if len(left_answer) == 0 {
			isMultipleHandshakeMessages = false
			answer, err = client.readFromServer()
			if err != nil {
				fmt.Println(err)
				client.Terminate()
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
		client.Terminate()
		os.Exit(1)
	}

	serverHelloDone, left_answer, err := model.ParseServerHelloDone(answer)
	if err != nil {
		fmt.Println(err)
		client.Terminate()
		os.Exit(1)
	}

	if len(left_answer) != 0 {
		fmt.Println("Answer should be empty after ServerHelloDone!", len(answer), answer)
	}

	if !isMultipleHandshakeMessages {
		client.messages = append(client.messages, helpers.IgnoreRecordHeader(answer)...)
	}

	fmt.Println(serverHelloDone)
}
