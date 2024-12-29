package model

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/helpers"
)

type ServerHello struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	ServerVersion     [2]byte
	ServerRandom      [32]byte
	SessionIDLength   [1]byte
	SessionID         []byte
	CipherSuite       [2]byte
	CompressionMethod [1]byte
	ExtensionsLength  [2]byte
	Extensions        []byte
}

func ParseServerHello(answer []byte) (ServerHello, []byte, error) {
	fmt.Println("Parsing Server Hello")
	offset := 0
	serverHello := ServerHello{}

	serverHello.RecordHeader = ParseRecordHeader(answer[0:5])
	offset += 5

	if serverHello.RecordHeader.Type != constants.RecordHandshake {
		return serverHello, answer, helpers.ServerHelloMissingError()
	}

	serverHello.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverHello.HandshakeHeader.MessageType != constants.HandshakeServerHello {
		return serverHello, answer, helpers.ServerHelloMissingError()
	}

	copy(serverHello.ServerVersion[:], answer[offset:offset+2])
	copy(serverHello.ServerRandom[:], answer[offset+2:offset+34])
	copy(serverHello.SessionIDLength[:], answer[offset+34:offset+35])

	sessionIDLengthInt := int(serverHello.SessionIDLength[0])
	if sessionIDLengthInt > 0 {
		serverHello.SessionID = answer[offset+35 : offset+sessionIDLengthInt+35]
		offset += sessionIDLengthInt
	}

	copy(serverHello.CipherSuite[:], answer[offset+35:offset+37])
	copy(serverHello.CompressionMethod[:], answer[offset+37:offset+38])
	offset += 38

	if offset < len(answer) {
		//multiple handshake message
		if answer[offset : offset+1][0] == 0x0b {
			//fix the record header Length
			serverHello.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(offset) - 5)
		} else {
			//parse the rest extensions
			copy(serverHello.ExtensionsLength[:], answer[offset:offset+2])
			offset += 2
			extensionLengthInt := int(helpers.ConvertByteArrayToUInt16(serverHello.ExtensionsLength))
			serverHello.Extensions = make([]byte, extensionLengthInt)
			copy(serverHello.Extensions[:], answer[offset:offset+extensionLengthInt])
			offset += extensionLengthInt

			//still has multiple handshake message
			if offset < len(answer) {
				serverHello.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(offset) - 5)
			}
		}
	}

	// serverHelloLength := int(helpers.ConvertByteArrayToUInt16(serverHello.RecordHeader.Length))
	// if serverHelloLength != (offset - 5) { // 5 is the length of RecordHeader

	//todo check the empty session ticket extension for confirm is server support session ticket reassumption.
	// empty session ticket 0x00 0x23 0x00 0x00

	// }

	return serverHello, answer[offset:], nil
}

func (serverHello ServerHello) SupportTicket() bool {
	offset := 0

	extensions := serverHello.Extensions

	for {
		if offset >= len(extensions) {
			break
		}

		ext_type := extensions[offset : offset+2]
		offset += 2

		if bytes.Equal(ext_type, []byte{0x00, 0x23}) {
			return true
		}

		ext_len := extensions[offset : offset+2]
		offset += 2 + int(binary.BigEndian.Uint16(ext_len))
	}

	return false
}

func (serverHello ServerHello) SaveJSON() {
	file, _ := os.OpenFile("ServerHello.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverHello)
}

func (serverHello ServerHello) String() string {
	out := "Server Hello\n"
	out += fmt.Sprint(serverHello.RecordHeader)
	out += fmt.Sprint(serverHello.HandshakeHeader)
	out += fmt.Sprintf("  Server Version.....: %6x - %s\n", serverHello.ServerVersion, constants.GTlsVersions.GetVersionForByteCode(serverHello.ServerVersion))
	out += fmt.Sprintf("  Server Random......: %6x\n", serverHello.ServerRandom)
	out += fmt.Sprintf("  Session ID length..: %6x\n", serverHello.SessionIDLength)
	out += fmt.Sprintf("  Session ID.........: %6x\n", serverHello.SessionID)
	out += fmt.Sprintf("  CipherSuite........: %6x - %s\n", serverHello.CipherSuite, constants.GCipherSuites.GetSuiteForByteCode(serverHello.CipherSuite))
	out += fmt.Sprintf("  CompressionMethod..: %6x\n", serverHello.CompressionMethod)
	out += fmt.Sprintf("  Extensions.........: %6x\n", serverHello.Extensions)

	return out
}

func (serverHello *ServerHello) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader      RecordHeader    `json:"RecordHeader"`
		HandshakeHeader   HandshakeHeader `json:"HandshakeHeader"`
		ServerVersion     string          `json:"SeverVersion"`
		ServerRandom      string          `json:"ServerRandom"`
		SessionID         string          `json:"SessionID"`
		CipherSuite       string          `json:"CipherSuite"`
		CompressionMethod uint8           `json:"CompressionMethod"`
	}{
		RecordHeader:      serverHello.RecordHeader,
		HandshakeHeader:   serverHello.HandshakeHeader,
		ServerVersion:     constants.GTlsVersions.GetVersionForByteCode(serverHello.ServerVersion),
		ServerRandom:      hex.EncodeToString(serverHello.ServerRandom[:]),
		SessionID:         hex.EncodeToString(serverHello.SessionID),
		CipherSuite:       constants.GCipherSuites.GetSuiteForByteCode(serverHello.CipherSuite),
		CompressionMethod: serverHello.CompressionMethod[0],
	})
}
