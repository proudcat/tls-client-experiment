package model

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/coreUtils"
	"github.com/proudcat/tls-client-experiment/cryptoHelpers"
	"github.com/proudcat/tls-client-experiment/helpers"
)

type ServerHandshakeFinished struct {
	RecordHeader    RecordHeader
	HandshakeHeader HandshakeHeader
	VerifyData      []byte
}

func ParseServerHandshakeFinished(serverKey, serverIV, answer []byte, seqNum byte) (ServerHandshakeFinished, []byte, error) {
	var offset uint32
	offset = 0

	serverHandshakeFinished := ServerHandshakeFinished{}
	serverHandshakeFinished.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	if serverHandshakeFinished.RecordHeader.Type != constants.RecordHandshake {
		fmt.Println("RecordType mismatch")
		return serverHandshakeFinished, answer, helpers.ServerHandshakeFinishedMissingError()
	}

	encryptedContent := answer[offset:]

	additionalData := coreUtils.MakeAdditionalData(seqNum, serverHandshakeFinished.RecordHeader.Type, serverHandshakeFinished.RecordHeader.ProtocolVersion)
	plaintext, err := cryptoHelpers.Decrypt(serverKey, serverIV, encryptedContent, additionalData)
	if err != nil {
		return serverHandshakeFinished, answer, err
	}

	offset = 0
	serverHandshakeFinished.HandshakeHeader = ParseHandshakeHeader(plaintext[offset : offset+4])
	offset += 4

	if serverHandshakeFinished.HandshakeHeader.MessageType != constants.HandshakeServerFinished {
		fmt.Println("HandshakeType mismatch")
		return serverHandshakeFinished, answer, helpers.ServerHandshakeFinishedMissingError()
	}

	serverHandshakeFinished.VerifyData = plaintext[offset:]

	return serverHandshakeFinished, answer[offset:], nil
}

func (serverHandshakeFinished ServerHandshakeFinished) SaveJSON() {
	file, _ := os.OpenFile("ServerHandshakeFinished.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverHandshakeFinished)
}

func (serverHandshakeFinished ServerHandshakeFinished) String() string {
	out := fmt.Sprintf("Server Handshake Finished\n")
	out += fmt.Sprint(serverHandshakeFinished.RecordHeader)
	out += fmt.Sprint(serverHandshakeFinished.HandshakeHeader)
	out += fmt.Sprintf("  VerifyData.........: %6x\n", serverHandshakeFinished.VerifyData)
	return out
}

func (serverHandshakeFinished *ServerHandshakeFinished) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader    RecordHeader    `json:"RecordHeader"`
		HandshakeHeader HandshakeHeader `json:"HandshakeHeader"`
		VerifyData      string          `json:"VerifyData"`
	}{
		RecordHeader:    serverHandshakeFinished.RecordHeader,
		HandshakeHeader: serverHandshakeFinished.HandshakeHeader,
		VerifyData:      hex.EncodeToString(serverHandshakeFinished.VerifyData),
	})
}
