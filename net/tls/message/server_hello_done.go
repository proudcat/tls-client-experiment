package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/buildin"
	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type ServerHelloDone struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
}

func (r *ServerHelloDone) FromBuffer(buf *buildin.Buffer) error {

	fmt.Println("Parsing Server Hello Done")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := r.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if r.RecordHeader.ContentType != types.RECORD_TYPE_HANDSHAKE {
		return fmt.Errorf("invalid record type %x", r.RecordHeader.ContentType)
	}

	offset_handshake_start := buf.Offset()

	if err := r.HandshakeHeader.FromBytes(buf.Next(types.HANDSHAKE_HEADER_SIZE)); err != nil {
		return err
	}

	if r.HandshakeHeader.Type != types.HS_TYPE_SERVER_HELLO_DONE {
		return fmt.Errorf("invalid handshake type %x", r.HandshakeHeader.Type)
	}

	offset_end := buf.Offset()

	if buf.Size() != 0 {
		return fmt.Errorf("invalid record size")
	}

	r.RecordHeader.Length = uint16(offset_end - offset_handshake_start)
	return nil
}

func (serverHelloDone ServerHelloDone) String() string {
	out := "\n------------------------- Server Hello Done ------------------------- \n"
	out += fmt.Sprint(serverHelloDone.RecordHeader)
	out += fmt.Sprint(serverHelloDone.HandshakeHeader)
	return out
}
