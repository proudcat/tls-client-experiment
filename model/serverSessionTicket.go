package model

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/helpers"
)

type ServerSessionTicket struct {
	RecordHeader RecordHeader
	LeftTimeHint []byte
	Payload      []byte
	Message      []byte
}

func ParseServerSessionTicket(answer []byte) (ServerSessionTicket, []byte, error) {
	var offset uint32
	offset = 0
	serverSessionTicket := ServerSessionTicket{}
	serverSessionTicket.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	if serverSessionTicket.RecordHeader.Type != constants.RecordHandshake {
		fmt.Println("RecordType mismatch")
		return serverSessionTicket, answer, helpers.ServerSessionTicketMissingError()
	}

	serverSessionTicket.Message = answer[offset:]

	handshakeType := int(answer[offset : offset+1][0])
	offset += 1

	if handshakeType != constants.HandshakeNewSessionTicket {
		fmt.Println("RecordType mismatch")
		return serverSessionTicket, answer, helpers.ServerSessionTicketMissingError()
	}

	// handshakeLen := binary.BigEndian.Uint32(answer[offset : offset+3])
	offset += 3

	serverSessionTicket.LeftTimeHint = answer[offset : offset+4]
	offset += 4

	ticketLength := uint32(binary.BigEndian.Uint16(answer[offset : offset+2]))
	offset += 2

	serverSessionTicket.Payload = answer[offset : offset+ticketLength]
	offset += ticketLength

	return serverSessionTicket, answer, nil
}

func (serverSessionTicket ServerSessionTicket) SaveJSON() {
	file, _ := os.OpenFile("ServerSessionTicket.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverSessionTicket)
}

func (serverSessionTicket ServerSessionTicket) String() string {
	out := fmt.Sprintln("Server New Ticket Session")
	out += fmt.Sprint(serverSessionTicket.RecordHeader)
	out += fmt.Sprintf("  LeftTimeHint....: %6x\n", serverSessionTicket.LeftTimeHint)
	out += fmt.Sprintf("  Payload.........: %6x\n", serverSessionTicket.Payload)
	return out
}

func (serverSessionTicket *ServerSessionTicket) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader RecordHeader `json:"RecordHeader"`
		LeftTimeHint []byte       `json:"LeftTimeHint"`
		Payload      []byte       `json:"Payload"`
	}{
		RecordHeader: serverSessionTicket.RecordHeader,
		Payload:      serverSessionTicket.Payload,
		LeftTimeHint: serverSessionTicket.LeftTimeHint,
	})
}
