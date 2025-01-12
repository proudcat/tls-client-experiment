package types

import (
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
)

const (
	EXTENSION_HEADER_SIZE = 4 //extension header size counter in bytes.
)

const (
	EXT_TYPE_GREASE_BEGIN                 uint16 = 0x3a3a
	EXT_TYPE_SERVER_NAME                  uint16 = 0x0000
	EXT_TYPE_EXTENDED_MASTER_SECRET       uint16 = 0x0017
	EXT_TYPE_RENEGOTIATION_INFO           uint16 = 0xff01
	EXT_TYPE_SUPPORTED_GROUPS             uint16 = 0x000a
	EXT_TYPE_EC_POINT_FORMATS             uint16 = 0x000b
	EXT_TYPE_SESSION_TICKET               uint16 = 0x0023
	EXT_TYPE_STATUS_REQUEST               uint16 = 0x0005
	EXT_TYPE_SIGNATURE_ALGORITHMS         uint16 = 0x000d
	EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP uint16 = 0x0012
	EXT_TYPE_GREASE_END                   uint16 = 0x4a4a
)

type ExtensionHeader struct {
	Type   uint16
	Length uint16
}

func (h *ExtensionHeader) FromBytes(bytes []byte) error {
	if len(bytes) != EXTENSION_HEADER_SIZE {
		return fmt.Errorf("invalid extension header size")
	}
	h.Type = binary.BigEndian.Uint16(bytes[0:2])
	h.Length = binary.BigEndian.Uint16(bytes[2:4])
	return nil
}

func (h ExtensionHeader) ToBytes() []byte {
	buf := common.Buffer{}
	buf.WriteUint16(h.Type)
	buf.WriteUint16(h.Length)
	return buf.Bytes()
}

type Extension struct {
	Header ExtensionHeader
	Data   []byte
}

func (e *Extension) FromBytes(data []byte) error {
	if len(data) < EXTENSION_HEADER_SIZE {
		return fmt.Errorf("invalid extension size")
	}
	if err := e.Header.FromBytes(data[:EXTENSION_HEADER_SIZE]); err != nil {
		return err
	}
	e.Data = data[EXTENSION_HEADER_SIZE:]
	return nil
}

func (e Extension) ToBytes() []byte {
	return append(e.Header.ToBytes(), e.Data...)
}

func (e Extension) Size() uint32 {
	return uint32(e.Header.Length + EXTENSION_HEADER_SIZE)
}

func (e Extension) String() string {
	return fmt.Sprintf("{ Type: %#04x, Length: %#04x, Data: % x }", e.Header.Type, e.Header.Length, e.Data)
}
