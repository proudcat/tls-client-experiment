package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/types"
)

type ServerChangeCipherSpec struct {
	RecordHeader types.RecordHeader
	Payload      []byte
}

func (r *ServerChangeCipherSpec) FromBuffer(buf *common.Buffer) error {

	fmt.Println("Parsing Server Change Cipher Spec")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := r.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if r.RecordHeader.ContentType != types.RECORD_TYPE_CHANGE_CIPHER_SPEC {
		return fmt.Errorf("invalid record type %d", r.RecordHeader.ContentType)
	}

	r.Payload = buf.Next(1)

	return nil
}

func (r ServerChangeCipherSpec) String() string {
	out := "\n------------------------- Server Change Cipher Spec ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprintf("Payload.........: %6x\n", r.Payload)
	return out
}
