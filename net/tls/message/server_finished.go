package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/buildin"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type ServerFinished struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	VerifyData      []byte
}

func (r *ServerFinished) FromBuffer(serverKey []byte, serverIV []byte, buf *buildin.Buffer) error {
	fmt.Println("Parsing Server Finished")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := r.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if r.RecordHeader.ContentType != types.RECORD_TYPE_HANDSHAKE {
		return fmt.Errorf("invalid record type %d", r.RecordHeader.ContentType)
	}

	plaintext, err := helpers.Decrypt(serverKey, serverIV, buf.Bytes(), 0, r.RecordHeader.ContentType, helpers.Uint16ToBytes(r.RecordHeader.Version))
	if err != nil {
		return err
	}

	r.HandshakeHeader.FromBytes(plaintext[0:4])

	if r.HandshakeHeader.Type != types.HS_TYPE_SERVER_FINISHED {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	r.VerifyData = plaintext[4:]

	return nil
}

func (r ServerFinished) String() string {
	out := "\n------------------------- Server Handshake Finished ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprint(r.HandshakeHeader)
	out += fmt.Sprintf("  VerifyData.........: %6x\n", r.VerifyData)
	return out
}
