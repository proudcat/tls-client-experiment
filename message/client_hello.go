package message

import (
	"crypto/rand"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/model"
	"github.com/proudcat/tls-client-experiment/types"
)

type ClientHelloMessage struct {
	Version                       uint16
	Random                        [32]byte
	SessionIdLength               byte
	CipherSuiteLength             uint16
	CipherSuite                   []uint16
	CompressionMethodsLength      byte
	CompressionMethods            []byte
	ExtensionsLength              uint16
	ExtensionGrease0              [4]byte
	ExtensionServerName           []byte
	ExtensionExtendedMasterSecret [4]byte
	ExtensionRenegotiation        [5]byte
	ExtensionSupportedGroups      []byte
	ExtensionEcPointFormats       [6]byte
	ExtensionSessionTicket        [4]byte
	// ExtensionStatusRequest              [9]byte
	ExtensionSignatureAlgorithm         []byte
	ExtensionSignedCertificateTimestamp [4]byte
	ExtensionGrease1                    [5]byte
	Extensions                          map[uint16][]byte
}

type ClientHello struct {
	RecordHeader                model.RecordHeader
	HandshakeHeader             model.HandshakeHeader
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

func NewClientHelloMessage(tls_version uint16, host string) *ClientHelloMessage {

	cipher_suites := []uint16{
		types.GREASE,
		types.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		types.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	server_name := []byte(host)
	server_name_len := uint16(len(server_name))

	buf := common.NewBuffer()
	buf.Write([]byte{0x00, 0x00})
	buf.WriteUint16(server_name_len + 5) // server name extension length
	buf.WriteUint16(server_name_len + 3) // server name list length
	buf.WriteUint8(0x00)                 // name type: host_name
	buf.WriteUint16(server_name_len)     // name length
	buf.Write(server_name)
	ext_server_name := buf.Drain()

	msg := &ClientHelloMessage{
		Version:                       tls_version,
		Random:                        common.Random32(),
		CipherSuite:                   cipher_suites,
		CipherSuiteLength:             uint16(len(cipher_suites) * 2),
		CompressionMethods:            []byte{0x00},
		CompressionMethodsLength:      0x01,
		SessionIdLength:               0x00,
		ExtensionGrease0:              [4]byte{0x3a, 0x3a, 0x00, 0x00},
		ExtensionRenegotiation:        [5]byte{0xff, 0x01, 0x00, 0x01, 0x00},
		ExtensionExtendedMasterSecret: [4]byte{0x00, 0x17, 0x00, 0x00},
		ExtensionSupportedGroups: []byte{
			0x00, 0x0a, // Type supported_groups
			0x00, 0x04, // Length
			0x00, 0x02, // Supported Groups List Length
			0x00, 0x17, // Supported Group: secp256r1
		},
		ExtensionEcPointFormats: [6]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00},
		ExtensionSessionTicket:  [4]byte{0x00, 0x23, 0x00, 0x00},
		// ExtensionStatusRequest:  [9]byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00},
		ExtensionSignatureAlgorithm: []byte{
			0x00, 0x0d, // Type signature_algorithms
			0x00, 0x06, // Length
			0x00, 0x04, // Signature Hash Algorithms Length
			0x04, 0x01, // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
			0x04, 0x03, // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
		},
		ExtensionSignedCertificateTimestamp: [4]byte{0x00, 0x12, 0x00, 0x00},
		ExtensionGrease1:                    [5]byte{0x4a, 0x4a, 0x00, 0x01, 0x00},
		ExtensionServerName:                 ext_server_name,
	}

	msg.ExtensionsLength = uint16(len(msg.ExtensionGrease0) +
		len(msg.ExtensionServerName) +
		len(msg.ExtensionExtendedMasterSecret) +
		len(msg.ExtensionRenegotiation) +
		len(msg.ExtensionSupportedGroups) +
		len(msg.ExtensionEcPointFormats) +
		len(msg.ExtensionSessionTicket) +
		// len(msg.ExtensionStatusRequest) +
		len(msg.ExtensionSignatureAlgorithm) +
		len(msg.ExtensionSignedCertificateTimestamp) +
		len(msg.ExtensionGrease1))

	return msg
}

func MakeClientHello(tlsVersion uint16, host string) ClientHello {
	clientHello := ClientHello{}

	recordHeader := model.RecordHeader{}
	recordHeader.Type = constants.RecordHandshake
	recordHeader.ProtocolVersion = constants.GTlsVersions.GetByteCodeForVersion("TLS 1.0")

	handshakeHeader := model.HandshakeHeader{}
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

func (clientHello ClientHello) String() string {
	out := "Client Hello\n"
	out += fmt.Sprintf("%8s", clientHello.RecordHeader)
	out += fmt.Sprintf("%8s", clientHello.HandshakeHeader)
	out += fmt.Sprintf("  Client Version.....: % x - %s\n", clientHello.ClientVersion, constants.GTlsVersions.GetVersionForByteCode(clientHello.ClientVersion))
	out += fmt.Sprintf("  Client Random......: % x\n", clientHello.ClientRandom)
	out += fmt.Sprintf("  Session ID.........: % x\n", clientHello.SessionID)
	out += fmt.Sprintf("  CipherSuite Len....: % x\n", clientHello.CipherSuiteLength)
	out += fmt.Sprintf("  CipherSuites.......:\n")
	for _, c := range helpers.ConvertByteArrayToCipherSuites(clientHello.CipherSuite) {
		out += fmt.Sprintf("       %s\n", c)
	}
	out += fmt.Sprintf("  CompressionMethods Len..: % x\n", clientHello.CompressionMethodsLength)
	out += fmt.Sprintf("  CompressionMethods..: % x\n", clientHello.CompressionMethods)

	out += fmt.Sprintf("  ExtensionsLength Len..: % x\n", clientHello.ExtensionsLength)
	out += fmt.Sprintf("  ExtensionSupportedGroups..: % x\n", clientHello.ExtensionSupportedGroups)
	out += fmt.Sprintf("  ExtensionSignatureAlgorithm..: % x\n", clientHello.ExtensionSignatureAlgorithm)
	out += fmt.Sprintf("  ExtensionServerName..: % x\n", clientHello.ExtensionServerName)

	return out
}
