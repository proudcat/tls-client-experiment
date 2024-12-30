package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/types"
)

type ClientHelloMessage struct {
	Version                  uint16
	Random                   [32]byte
	SessionIdLength          byte
	CipherSuiteLength        uint16
	CipherSuite              []uint16
	CompressionMethodsLength byte
	CompressionMethods       []byte
	ExtensionsLength         uint16
	Extensions               []types.Extension
}

func NewClientHelloMessage(tls_version uint16, host string) ClientHelloMessage {

	cipher_suites := []uint16{
		types.GREASE,
		types.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		types.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}

	cipher_suite_len := uint16(len(cipher_suites) * 2)
	client_random := helpers.Random32()

	msg := ClientHelloMessage{
		Version:                  tls_version,
		Random:                   client_random,
		CipherSuite:              cipher_suites,
		CipherSuiteLength:        cipher_suite_len,
		CompressionMethodsLength: 0x01,
		CompressionMethods:       []byte{0x00},
		SessionIdLength:          0x00,
	}

	msg.AddExtension(types.EXT_TYPE_GREASE_BEGIN, []byte{0x00, 0x00})

	server_name := []byte(host)
	server_name_len := uint16(len(server_name))

	buf := common.NewBuffer()
	buf.WriteUint16(server_name_len + 3) // server name list length
	buf.WriteUint8(0x00)                 // name type: host_name
	buf.WriteUint16(server_name_len)     // name length
	buf.Write(server_name)
	ext_server_name := buf.Drain()

	msg.AddExtension(types.EXT_TYPE_SERVER_NAME, ext_server_name)
	msg.AddExtension(types.EXT_TYPE_EXTENDED_MASTER_SECRET, nil)
	msg.AddExtension(types.EXT_TYPE_RENEGOTIATION_INFO, []byte{0x00})
	msg.AddExtension(types.EXT_TYPE_SUPPORTED_GROUPS, []byte{
		0x00, 0x08, // List Length
		0xba, 0xba, // GREASE
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
	})
	msg.AddExtension(types.EXT_TYPE_EC_POINT_FORMATS, []byte{
		0x01, // List Length
		0x00, // Uncompressed
	})

	msg.AddExtension(types.EXT_TYPE_SESSION_TICKET, nil)
	msg.AddExtension(types.EXT_TYPE_STATUS_REQUEST, []byte{0x01, 0x00, 0x00, 0x00, 0x00})
	msg.AddExtension(types.EXT_TYPE_SIGNATURE_ALGORITHMS, []byte{
		0x00, 0x04, // List Length TODO more signatures
		0x04, 0x01, // Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
		0x04, 0x03, // Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
	})

	msg.AddExtension(types.EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP, nil)
	msg.AddExtension(types.EXT_TYPE_GREASE_END, []byte{0x00})

	var ext_len uint32 = 0

	for _, ext := range msg.Extensions {
		ext_len += ext.Size()
	}

	msg.ExtensionsLength = uint16(ext_len)

	return msg
}

func (msg *ClientHelloMessage) AddExtension(ext_type uint16, data []byte) {
	ext := types.Extension{
		Header: types.ExtensionHeader{
			Type:   ext_type,
			Length: uint16(len(data)),
		},
		Data: data,
	}
	msg.Extensions = append(msg.Extensions, ext)
}

func (msg ClientHelloMessage) Size() int {
	var size = 0

	size += 2                                 // version
	size += len(msg.Random)                   // random
	size += 1                                 // session id length
	size += int(msg.SessionIdLength)          // session id
	size += 2                                 // cipher suite length
	size += int(msg.CipherSuiteLength)        //cipher suites
	size += 1                                 // compression methods length
	size += int(msg.CompressionMethodsLength) // compression methods
	size += 2                                 // extensions length

	for _, ext := range msg.Extensions {
		size += int(ext.Size()) //extensions length
	}

	return size
}

func (msg ClientHelloMessage) ToBytes() []byte {
	buf := common.NewBuffer()
	buf.WriteUint16(msg.Version)
	buf.Write(msg.Random[:])
	buf.WriteUint8(msg.SessionIdLength)
	buf.WriteUint16(msg.CipherSuiteLength)
	for _, c := range msg.CipherSuite {
		buf.WriteUint16(c)
	}
	buf.WriteUint8(msg.CompressionMethodsLength)
	buf.Write(msg.CompressionMethods)
	buf.WriteUint16(msg.ExtensionsLength)

	for _, ext := range msg.Extensions {
		buf.Write(ext.ToBytes())
	}

	return buf.Drain()
}

func (msg ClientHelloMessage) String() string {
	out := ""
	out += fmt.Sprintf("Version...........: %#04x - %s\n", msg.Version, types.VersionName(msg.Version))
	out += fmt.Sprintf("Random............: % x\n", msg.Random)
	out += fmt.Sprintf("Session ID........: %#02x\n", msg.SessionIdLength)
	out += fmt.Sprintf("CipherSuite Len...: %#04x\n", msg.CipherSuiteLength)
	out += fmt.Sprintf("CipherSuites......:\n")
	for _, c := range msg.CipherSuite {
		out += fmt.Sprintf("  %s\n", types.CipherSuites[c].Name)
	}
	out += fmt.Sprintf("CompressionMethods Len..: %#02x\n", msg.CompressionMethodsLength)
	out += fmt.Sprintf("CompressionMethods......: % x\n", msg.CompressionMethods)
	out += fmt.Sprintf("ExtensionsLength Len....: %#04x\n", msg.ExtensionsLength)
	out += fmt.Sprintf("Extensions..............:\n")
	for _, ext := range msg.Extensions {
		out += fmt.Sprintf("  %s\n", ext)
	}
	return out
}

type ClientHello struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	Message         ClientHelloMessage
}

func NewClientHello(tls_version uint16, host string) ClientHello {
	msg := NewClientHelloMessage(tls_version, host)
	msg_size := msg.Size()

	record := ClientHello{
		RecordHeader: types.RecordHeader{
			ContentType: types.RECORD_TYPE_HANDSHAKE,
			Version:     types.PROTOCOL_VERSION_TLS10,
			Length:      uint16(msg_size + types.HANDSHAKE_HEADER_SIZE),
		},
		HandshakeHeader: types.HandshakeHeader{
			Type:   types.HS_TYPE_CLIENT_HELLO,
			Length: uint32(msg_size),
		},
		Message: msg,
	}
	return record
}

func (clientHello ClientHello) ToBytes() []byte {
	buf := common.NewBuffer()
	buf.Write(clientHello.RecordHeader.ToBytes())
	buf.Write(clientHello.HandshakeHeader.ToBytes())
	buf.Write(clientHello.Message.ToBytes())
	return buf.Drain()
}

func (clientHello ClientHello) String() string {
	out := "\n------------------------- Client Hello ------------------------- \n"
	out += fmt.Sprintf("%4s", clientHello.RecordHeader)
	out += fmt.Sprintf("%4s", clientHello.HandshakeHeader)
	out += fmt.Sprintf("%8s", clientHello.Message)
	return out
}
