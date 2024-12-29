package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/helpers"
)

type ClientHello struct {
	RecordHeader                RecordHeader
	HandshakeHeader             HandshakeHeader
	ClientVersion               [2]byte
	ClientRandom                [32]byte
	SessionID                   [1]byte
	CipherSuiteLength           [2]byte
	CipherSuite                 []byte
	CompressionMethodsLength    [1]byte
	CompressionMethods          []byte
	ExtensionsLength            [2]byte
	ExtensionSupportedGroups    []byte
	ExtensionSignatureAlgorithm []byte
	ExtensionServerName         []byte
}

func MakeClientHello(tlsVersion uint16, host string) ClientHello {
	clientHello := ClientHello{}

	recordHeader := RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.0")

	handshakeHeader := HandshakeHeader{}
	handshakeHeader.MessageType = constants.HandshakeClientHello

	clientHello.ClientVersion = helpers.ConvertIntToByteArray(tlsVersion)
	clientRandom := make([]byte, 32)
	_, err := rand.Read(clientRandom)
	if err != nil {
		fmt.Println(err)
	}

	copy(clientHello.ClientRandom[:], clientRandom)

	clientHello.SessionID = [1]byte{0x00}

	suitesByteCode := constants.GCipherSuites.GetSuiteByteCodes(constants.GCipherSuites.GetAllSuites())
	// According to TLS 1.2 documentation, part 7.4.3:
	// Server Key Exchange Message is sent by the server only for certain key exchange message, including ECDHE

	clientHello.CipherSuite = suitesByteCode[:]
	clientHello.CipherSuiteLength = helpers.ConvertIntToByteArray(uint16(len(suitesByteCode)))

	clientHello.CompressionMethods = []byte{0x00}
	clientHello.CompressionMethodsLength = [1]byte{0x01}

	clientHello.ExtensionSupportedGroups = []byte{
		0x00, 0x0a, // Type supported_groups
		0x00, 0x04, // Length
		0x00, 0x02, // Supported Groups List Length
		0x00, 0x17, // Supported Group: secp256r1
	}

	clientHello.ExtensionSignatureAlgorithm = []byte{
		0x00, 0x0d, // Type signature_algorithms
		0x00, 0x06, // Length
		0x00, 0x04, // Signature Hash Algorithms Length
		0x04, 0x01, // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
		0x04, 0x03, // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
	}

	serverName := []byte(host)
	serverNameExtensionLen := helpers.ConvertIntToByteArray(uint16(len(serverName) + 5))
	serverNameListLen := helpers.ConvertIntToByteArray(uint16(len(serverName) + 3))
	serverNameLen := helpers.ConvertIntToByteArray(uint16(len(serverName)))

	extensionServerName := []byte{
		0x00, 0x00, // Extension type: server_name
	}

	extensionServerName = append(extensionServerName, serverNameExtensionLen[:]...)
	extensionServerName = append(extensionServerName, serverNameListLen[:]...)
	extensionServerName = append(extensionServerName, 0x00) // Type: host name
	extensionServerName = append(extensionServerName, serverNameLen[:]...)
	extensionServerName = append(extensionServerName, serverName[:]...)
	clientHello.ExtensionServerName = extensionServerName

	clientHello.ExtensionsLength = helpers.ConvertIntToByteArray(uint16(len(clientHello.ExtensionSupportedGroups) + len(clientHello.ExtensionSignatureAlgorithm) + len(clientHello.ExtensionServerName)))

	handshakeHeader.MessageLength = clientHello.getHandshakeHeaderLength()
	clientHello.HandshakeHeader = handshakeHeader

	recordHeader.Length = clientHello.getRecordLength()
	clientHello.RecordHeader = recordHeader

	return clientHello
}

func (clientHello ClientHello) getHandshakeHeaderLength() [3]byte {
	var length [3]byte
	var k int

	k = len(clientHello.ClientVersion)
	k += len(clientHello.ClientRandom)
	k += len(clientHello.SessionID)
	k += len(clientHello.CipherSuiteLength)
	k += len(clientHello.CipherSuite)
	k += len(clientHello.CompressionMethodsLength)
	k += len(clientHello.CompressionMethods)
	k += len(clientHello.ExtensionsLength)
	k += len(clientHello.ExtensionSupportedGroups)
	k += len(clientHello.ExtensionSignatureAlgorithm)
	k += len(clientHello.ExtensionServerName)

	tmp := helpers.ConvertIntToByteArray(uint16(k))
	length[0] = 0x00
	length[1] = tmp[0]
	length[2] = tmp[1]

	return length
}

func (clientHello ClientHello) getRecordLength() [2]byte {
	tmp := int(helpers.Convert3ByteArrayToUInt32(clientHello.HandshakeHeader.MessageLength))
	tmp += 1 // size of MessageType
	tmp += len(clientHello.HandshakeHeader.MessageLength)

	return helpers.ConvertIntToByteArray(uint16(tmp))
}

func (clientHello ClientHello) GetClientHelloPayload() []byte {
	var payload []byte

	payload = append(payload, clientHello.RecordHeader.Type)
	payload = append(payload, clientHello.RecordHeader.ProtocolVersion[:]...)
	payload = append(payload, clientHello.RecordHeader.Length[:]...)
	payload = append(payload, clientHello.HandshakeHeader.MessageType)
	payload = append(payload, clientHello.HandshakeHeader.MessageLength[:]...)
	payload = append(payload, clientHello.ClientVersion[:]...)
	payload = append(payload, clientHello.ClientRandom[:]...)
	payload = append(payload, clientHello.SessionID[:]...)
	payload = append(payload, clientHello.CipherSuiteLength[:]...)
	payload = append(payload, clientHello.CipherSuite[:]...)
	payload = append(payload, clientHello.CompressionMethodsLength[:]...)
	payload = append(payload, clientHello.CompressionMethods...)
	payload = append(payload, clientHello.ExtensionsLength[:]...)
	payload = append(payload, clientHello.ExtensionSupportedGroups...)
	payload = append(payload, clientHello.ExtensionSignatureAlgorithm...)
	payload = append(payload, clientHello.ExtensionServerName...)

	return payload
}

func (clientHello ClientHello) SaveJSON() {
	file, _ := os.OpenFile("ClientHello.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&clientHello)
}

func (clientHello ClientHello) String() string {
	out := fmt.Sprintf("Client Hello\n")
	out += fmt.Sprint(clientHello.RecordHeader)
	out += fmt.Sprint(clientHello.HandshakeHeader)
	out += fmt.Sprintf("  Client Version.....: %6x - %s\n", clientHello.ClientVersion, constants.GTlsVersions.GetVersionForByteCode(clientHello.ClientVersion))
	out += fmt.Sprintf("  Client Random......: %6x\n", clientHello.ClientRandom)
	out += fmt.Sprintf("  Session ID.........: %6x\n", clientHello.SessionID)
	out += fmt.Sprintf("  CipherSuite Len....: %6x\n", clientHello.CipherSuiteLength)
	out += fmt.Sprintf("  CipherSuites.......:\n")
	for _, c := range helpers.ConvertByteArrayToCipherSuites(clientHello.CipherSuite) {
		out += fmt.Sprintf("       %s\n", c)
	}
	out += fmt.Sprintf("  CompressionMethods Len..: %6x\n", clientHello.CompressionMethodsLength)
	out += fmt.Sprintf("  CompressionMethods..: %6x\n", clientHello.CompressionMethods)

	out += fmt.Sprintf("  ExtensionsLength Len..: %6x\n", clientHello.ExtensionsLength)
	out += fmt.Sprintf("  ExtensionSupportedGroups..: %6x\n", clientHello.ExtensionSupportedGroups)
	out += fmt.Sprintf("  ExtensionSignatureAlgorithm..: %6x\n", clientHello.ExtensionSignatureAlgorithm)
	out += fmt.Sprintf("  ExtensionServerName..: %6x\n", clientHello.ExtensionServerName)

	return out
}

func (clientHello *ClientHello) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader             RecordHeader    `json:"RecordHeader"`
		HandshakeHeader          HandshakeHeader `json:"HandshakeHeader"`
		ClientVersion            string          `json:"ClientVersion"`
		ClientRandom             string          `json:"ClientRandom"`
		SessionID                uint8           `json:"SessionID"`
		CipherSuiteLength        uint16          `json:"CipherSuiteLength"`
		CipherSuites             []string        `json:"CipherSuites"`
		CompressionMethodsLength uint8           `json:"CompressionMethodsLength"`
		CompressionMethods       string          `json:"CompressionMethods"`
	}{
		RecordHeader:             clientHello.RecordHeader,
		HandshakeHeader:          clientHello.HandshakeHeader,
		ClientVersion:            constants.GTlsVersions.GetVersionForByteCode(clientHello.ClientVersion),
		ClientRandom:             hex.EncodeToString(clientHello.ClientRandom[:]),
		SessionID:                clientHello.SessionID[0],
		CipherSuiteLength:        helpers.ConvertByteArrayToUInt16(clientHello.CipherSuiteLength),
		CipherSuites:             helpers.ConvertByteArrayToCipherSuites(clientHello.CipherSuite),
		CompressionMethodsLength: clientHello.CompressionMethodsLength[0],
		CompressionMethods:       hex.EncodeToString(clientHello.CompressionMethods),
	})
}
