package types

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/helpers"
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
	Length uint32 // 24 bits
}

func (h *HandshakeHeader) FromBytes(bytes []byte) error {
	if len(bytes) != HANDSHAKE_HEADER_SIZE {
		return fmt.Errorf("invalid handshake header size")
	}
	h.Type = bytes[0]
	length_bytes := [3]byte{}
	copy(length_bytes[:], bytes[1:4])
	h.Length = helpers.Bytes2Uint24(length_bytes)
	return nil
}

func (h HandshakeHeader) ToBytes() []byte {
	buf := common.NewBuffer()
	buf.WriteUint8(h.Type)
	buf.WriteUint24(h.Length)
	return buf.Drain()
}

func (h HandshakeHeader) Size() uint32 {
	return h.Length + HANDSHAKE_HEADER_SIZE
}

func (h HandshakeHeader) String() string {
	out := "Handshake Header\n"
	out += fmt.Sprintf("    Type............: %#02x\n", h.Type)
	out += fmt.Sprintf("    Length..........: %#06x\n", h.Length)
	return out
}
