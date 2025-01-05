package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/types"
	"github.com/proudcat/tls-client-experiment/zkp"
)

const (
	verifyDataLength = 12
)

type ClientFinished struct {
	RecordHeader     types.RecordHeader
	HandshakeHeader  types.HandshakeHeader
	VerifyData       []byte
	EncryptedContent []byte
}

func MakeClientFinished(params *helpers.SecurityParameters, verifyData []byte, tls_version uint16, seqNum byte) (*ClientFinished, error) {
	record := &ClientFinished{
		RecordHeader: types.RecordHeader{
			ContentType: types.RECORD_TYPE_HANDSHAKE,
			Version:     tls_version,
		},
		HandshakeHeader: types.HandshakeHeader{
			Type:   types.HS_TYPE_CLIENT_FINISHED,
			Length: zkp.NewUint24(verifyDataLength),
		},
	}

	record.VerifyData = verifyData

	buf := zkp.Buffer{}
	buf.Write(record.HandshakeHeader.ToBytes())
	buf.Write(record.VerifyData)

	plaintext := buf.Bytes()
	encryptedContent, err := helpers.Encrypt(params.ClientKey, params.ClientIV, plaintext, seqNum, record.RecordHeader.ContentType, helpers.Uint16ToBytes(tls_version))

	if err != nil {
		return record, err
	}

	record.EncryptedContent = encryptedContent
	record.RecordHeader.Length = uint16(len(encryptedContent))

	return record, nil
}

func (clientHandshakeFinished ClientFinished) ToBytes() []byte {
	payload := append(clientHandshakeFinished.RecordHeader.ToBytes(), clientHandshakeFinished.EncryptedContent...)
	return payload
}

func (r ClientFinished) String() string {
	out := "\n------------------------- Client Handshake Finished ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprint(r.HandshakeHeader)
	out += fmt.Sprintf("  VerifyData.........: % x\n", r.VerifyData)
	out += fmt.Sprintf("  EncryptedContent...: % x\n", r.EncryptedContent)
	return out
}
