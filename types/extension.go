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
	EXT_TYPE_SERVER_NAME uint16 = 0x0000
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
	buf := common.NewBuffer()
	buf.WriteUint16(h.Type)
	buf.WriteUint16(h.Length)
	return buf.Drain()
}

func (h ExtensionHeader) String() string {
	out := "Extension Header\n"
	out += fmt.Sprintf("  Type............: %#04x\n", h.Type)
	out += fmt.Sprintf("  Length..........: %#04x\n", h.Length)
	return out
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
	buf := common.NewBuffer()
	buf.Write(e.Header.ToBytes())
	buf.Write(e.Data)
	return buf.Drain()
}
