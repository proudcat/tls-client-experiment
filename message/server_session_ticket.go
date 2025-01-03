package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/types"
	"github.com/proudcat/tls-client-experiment/zkp"
)

type ServerSessionTicket struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	LeftTimeHint    []byte
	Payload         []byte
	Message         []byte
}

func (r *ServerSessionTicket) FromBuffer(buf *zkp.Buffer) error {
	fmt.Println("Parsing Server Session Ticket")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := r.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if r.RecordHeader.ContentType != types.RECORD_TYPE_HANDSHAKE {
		return fmt.Errorf("invalid record type %d", r.RecordHeader.ContentType)
	}

	if err := r.HandshakeHeader.FromBytes(buf.Next(types.HANDSHAKE_HEADER_SIZE)); err != nil {
		return err
	}

	if r.HandshakeHeader.Type != types.HS_TYPE_NEW_SESSION_TICKET {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	offset_payload_start := buf.Offset()

	r.LeftTimeHint = buf.Next(4)
	ticketLength := buf.NextUint16()

	ticket := buf.Next(uint32(ticketLength))

	r.Payload = ticket

	offset_end := buf.Offset()

	if r.HandshakeHeader.Length.Uint32() != offset_end-offset_payload_start {
		return fmt.Errorf("invalid handshake size")
	}

	if buf.Size() > 0 {
		panic("buf size is not zero may multiple handshake messages here!!!!")
	}

	//multiple handshake message
	// r.RecordHeader.Length = uint16(offset_end - offset_handshake_start)

	return nil
}

func (r ServerSessionTicket) String() string {
	out := "\n------------------------- Server New Ticket Session ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprint(r.HandshakeHeader)
	out += fmt.Sprintf("LeftTimeHint....: %6x\n", r.LeftTimeHint)
	out += fmt.Sprintf("Payload.........: %6x\n", r.Payload)
	return out
}
