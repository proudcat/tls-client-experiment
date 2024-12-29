package types

import (
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
)

const (
	HANDSHAKE_HEADER_SIZE = 4 //handshake header size counter in bytes.
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
	h.Length = binary.BigEndian.Uint32(bytes[1:4])
	return nil
}

func (h HandshakeHeader) ToBytes() []byte {
	buf := common.NewBuffer()
	buf.WriteUint8(h.Type)
	buf.WriteUint24(h.Length)
	return buf.Drain()
}

func (h HandshakeHeader) String() string {
	out := "Handshake Header\n"
	out += fmt.Sprintf("    Type............: % x\n", h.Type)
	out += fmt.Sprintf("    Length..........: % x\n", h.Length)
	return out
}
