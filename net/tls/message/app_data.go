package message

import (
	"fmt"

	"github.com/proudcat/tls-client-experiment/buildin"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type AppData struct {
	RecordHeader types.RecordHeader
	Data         []byte
	Payload      []byte
}

func (app AppData) String() string {
	out := "\n------------------------- Application Data ------------------------- \n"
	out += fmt.Sprint(app.RecordHeader)
	// out += fmt.Sprintf("Payload....: % x\n", app.Payload)
	out += fmt.Sprintf("................Data................:\n% s\n", app.Data)
	return out
}

func (app AppData) Bytes() []byte {
	return append(app.RecordHeader.ToBytes(), app.Payload...)
}

func (app *AppData) FromBuffer(key []byte, iv []byte, seq byte, buf *buildin.Buffer) error {
	fmt.Println("Parsing Server Application Data")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := app.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if app.RecordHeader.ContentType != types.RECORD_TYPE_APPLICATION_DATA {
		return fmt.Errorf("invalid record type %d", app.RecordHeader.ContentType)
	}

	app.Payload = buf.Bytes()

	content, err := helpers.Decrypt(key, iv, app.Payload, seq, app.RecordHeader.ContentType, helpers.Uint16ToBytes(app.RecordHeader.Version))
	if err != nil {
		return err
	}

	app.Data = content

	return nil
}

func NewAppData(key, iv, data []byte, tls_version uint16, seq byte) (*AppData, error) {

	record_content_type := types.RECORD_TYPE_APPLICATION_DATA

	payload, err := helpers.Encrypt(key, iv, data, seq, record_content_type, helpers.Uint16ToBytes(tls_version))

	if err != nil {
		return nil, err
	}

	return &AppData{
		RecordHeader: types.RecordHeader{
			ContentType: record_content_type,
			Version:     tls_version,
			Length:      uint16(len(payload)),
		},
		Data:    data,
		Payload: payload,
	}, nil
}
