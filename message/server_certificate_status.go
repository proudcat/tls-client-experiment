package message

import (
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/types"
	"github.com/proudcat/tls-client-experiment/zkp"
)

type ServerCertificateStatusParams struct {
	StatusType []byte
	Payload    []byte
}

type ServerCertificateStatus struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	Params          ServerCertificateStatusParams
}

func (r *ServerCertificateStatus) FromBuffer(buf *zkp.Buffer) error {

	fmt.Println("Parsing Server Certificate Status")

	r.Params = ServerCertificateStatusParams{}

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

	r.Params.StatusType = buf.Next(1)

	payload_len := binary.BigEndian.Uint32(append([]byte{0}, buf.Next(3)...))

	r.Params.Payload = buf.Next(payload_len)

	offset_end := buf.Offset()

	if r.HandshakeHeader.Length.Uint32() != offset_end-offset_payload_start {
		return fmt.Errorf("invalid handshake size")
	}

	//fix record header length  if multiple messages
	r.RecordHeader.Length = uint16(offset_end - offset_handshake_start)

	// buf.ClearKeys()
	return nil
}

func (certificateStatus ServerCertificateStatus) String() string {
	out := "\n------------------------- Server Certificate Status ------------------------- \n"
	out += fmt.Sprint(certificateStatus.RecordHeader)
	out += fmt.Sprint(certificateStatus.HandshakeHeader)
	out += fmt.Sprintf("StatusType....: %6x\n", certificateStatus.Params.StatusType)
	out += fmt.Sprintf("Payload.........: %6x\n", certificateStatus.Params.Payload)
	return out
}
