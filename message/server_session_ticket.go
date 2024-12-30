package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/types"
)

type ServerSessionTicket struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	LeftTimeHint    []byte
	Payload         []byte
	Message         []byte
}

func (r *ServerSessionTicket) FromBuffer(buf *common.Buffer) error {
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

	buf.AddKey("handshake_start")

	if err := r.HandshakeHeader.FromBytes(buf.Next(types.HANDSHAKE_HEADER_SIZE)); err != nil {
		return err
	}

	if r.HandshakeHeader.Type != types.HS_TYPE_NEW_SESSION_TICKET {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	buf.AddKey("payload_start")

	r.LeftTimeHint = buf.Next(4)
	ticketLength, err := buf.ReadUint16()

	if err != nil {
		return err
	}

	ticket, err := buf.ReadBytes(int(ticketLength))
	if err != nil {
		return err
	}

	r.Payload = ticket

	buf.AddKey("end")

	if int(r.HandshakeHeader.Length) != buf.ClipSize("payload_start", "end") {
		return fmt.Errorf("invalid handshake size")
	}

	if buf.Size() > 0 {
		panic("buf size is not zero may multiple handshake messages here!!!!")
	}

	//multiple handshake message
	// r.RecordHeader.Length = uint16(buf.ClipSize("handshake_start", "end"))

	buf.ClearKeys()
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
