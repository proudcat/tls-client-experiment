package types

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
)

const (
	HANDSHAKE_HEADER_SIZE = 4 //handshake header size counter in bytes.
)

const (
	HS_TYPE_CLIENT_HELLO              = 0x01
	HS_TYPE_SERVER_HELLO              = 0x02
	HS_TYPE_NEW_SESSION_TICKET        = 0x04
	HS_TYPE_SERVER_CERTIFICATE        = 0x0b
	HS_TYPE_SERVER_KEY_EXCHANGE       = 0x0c
	HS_TYPE_SERVER_HELLO_DONE         = 0x0e
	HS_TYPE_CLIENT_KEY_EXCHANGE       = 0x10
	HS_TYPE_CLIENT_FINISHED           = 0x14
	HS_TYPE_SERVER_FINISHED           = 0x14
	HS_TYPE_SERVER_CERTIFICATE_STATUS = 0x16
)

type HandshakeHeader struct {
	Type   uint8
	Length common.Uint24
}

func (h *HandshakeHeader) FromBytes(bytes []byte) error {
	if len(bytes) != HANDSHAKE_HEADER_SIZE {
		return fmt.Errorf("invalid handshake header size")
	}
	h.Type = bytes[0]
	h.Length.FromBytes(bytes[1:4])
	return nil
}

func (h HandshakeHeader) ToBytes() []byte {
	buf := common.Buffer{}
	buf.WriteUint8(h.Type)
	buf.WriteUint24(h.Length)
	return buf.Bytes()
}

func (h HandshakeHeader) Size() uint32 {
	return h.Length.Uint32() + HANDSHAKE_HEADER_SIZE
}

func (h HandshakeHeader) String() string {
	out := "Handshake Header\n"
	out += fmt.Sprintf("    Type............: %#02x\n", h.Type)
	out += fmt.Sprintf("    Length..........: % d\n", h.Length)
	return out
}
