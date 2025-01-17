package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/buildin"
	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type ClientChangeCipherSpec struct {
	RecordHeader types.RecordHeader
	Payload      byte
}

func NewClientChangeCipherSpec(tls_version uint16) *ClientChangeCipherSpec {

	record := &ClientChangeCipherSpec{
		RecordHeader: types.RecordHeader{
			ContentType: types.RECORD_TYPE_CHANGE_CIPHER_SPEC,
			Version:     tls_version,
			Length:      0x0001,
		},
		Payload: 1,
	}
	return record
}

func (r ClientChangeCipherSpec) ToBytes() []byte {
	buf := buildin.Buffer{}
	buf.Write(r.RecordHeader.ToBytes())
	buf.WriteUint8(r.Payload)
	return buf.Bytes()
}

func (r ClientChangeCipherSpec) String() string {
	out := "\n------------------------- Client Change Cipher Spec ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprintf("Payload....: %x\n", r.Payload)
	return out
}
