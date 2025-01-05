package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/types"
	"github.com/proudcat/tls-client-experiment/zkp"
)

// type ServerCertificateStatusParams struct {
// 	StatusType []byte
// 	Payload    []byte
// }

type ServerCertificateStatus struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	StatusType      byte
	Payload         []byte
	// Params          ServerCertificateStatusParams
}

func (r *ServerCertificateStatus) FromBuffer(buf *zkp.Buffer) error {

	fmt.Println("Parsing Server Certificate Status")

	// r.Params = ServerCertificateStatusParams{}

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := r.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if r.RecordHeader.ContentType != types.RECORD_TYPE_HANDSHAKE {
		return fmt.Errorf("invalid record type %d", r.RecordHeader.ContentType)
	}

	offset_handshake_start := buf.Offset()

	if err := r.HandshakeHeader.FromBytes(buf.Next(types.HANDSHAKE_HEADER_SIZE)); err != nil {
		return err
	}

	if r.HandshakeHeader.Type != types.HS_TYPE_SERVER_CERTIFICATE_STATUS {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	offset_payload_start := buf.Offset()

	r.StatusType = buf.NextUint8()

	payload_len := buf.NextUint24().Uint32()

	r.Payload = buf.Next(payload_len)

	offset_end := buf.Offset()

	if r.HandshakeHeader.Length.Uint32() != offset_end-offset_payload_start {
		return fmt.Errorf("invalid handshake size")
	}

	//fix record header length  if multiple messages
	r.RecordHeader.Length = uint16(offset_end - offset_handshake_start)

	return nil
}

func (me ServerCertificateStatus) String() string {
	out := "\n------------------------- Server Certificate Status ------------------------- \n"
	out += fmt.Sprint(me.RecordHeader)
	out += fmt.Sprint(me.HandshakeHeader)
	out += fmt.Sprintf("StatusType....: %x\n", me.StatusType)
	out += fmt.Sprintf("Payload.........: % x\n", me.Payload)
	return out
}
