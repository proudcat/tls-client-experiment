package types

import (
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
)

const (
	RECORD_HEADER_SIZE = 5 //record header size counter in bytes.
)

type RecordHeader struct {
	ContentType uint8
	Version     uint16
	Length      uint16
}

func (recordHeader *RecordHeader) FromBytes(bytes []byte) error {
	if len(bytes) != RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record header size")
	}
	recordHeader.ContentType = bytes[0]
	recordHeader.Version = binary.BigEndian.Uint16(bytes[1:3])
	recordHeader.Length = binary.BigEndian.Uint16(bytes[3:5])
	return nil
}

func (recordHeader RecordHeader) ToBytes() []byte {
	buf := common.NewBuffer()
	buf.WriteUint8(recordHeader.ContentType)
	buf.WriteUint16(recordHeader.Version)
	buf.WriteUint16(recordHeader.Length)
	return buf.PeekAllBytes()
}

func (h RecordHeader) String() string {
	out := "Record Header\n"
	out += fmt.Sprintf("    ContentType.....: % x\n", h.ContentType)
	out += fmt.Sprintf("    Version.........: % x\n", h.Version)
	out += fmt.Sprintf("    Length..........: % x\n", h.Length)
	return out
}
