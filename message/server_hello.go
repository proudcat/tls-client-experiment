package message

import (
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/types"
)

type ServerHelloMessage struct {
	Version           uint16
	Random            [32]byte
	SessionIDLength   byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod byte
	ExtensionsLength  uint16
	Extensions        []types.Extension
}

func (msg ServerHelloMessage) String() string {
	out := ""
	out += fmt.Sprintf("Version.....: %#04x - %s\n", msg.Version, types.VersionName(msg.Version))
	out += fmt.Sprintf("Random......: % x\n", msg.Random)
	out += fmt.Sprintf("Session ID length..: %#02x\n", msg.SessionIDLength)
	out += fmt.Sprintf("Session ID.........: % x\n", msg.SessionID)
	out += fmt.Sprintf("CipherSuites.......:\n")
	out += fmt.Sprintf("CipherSuite........: %#04x - %s\n", msg.CipherSuite, types.CipherSuites[msg.CipherSuite].Name)
	out += fmt.Sprintf("CompressionMethod..: %#02x\n", msg.CompressionMethod)
	out += fmt.Sprintf("Extensions.........:\n")
	for _, ext := range msg.Extensions {
		out += fmt.Sprintf("  %s\n", ext)
	}
	return out
}

type ServerHello struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	Message         ServerHelloMessage
}

func (r *ServerHello) FromBuffer(buf *common.Buffer) error {
	fmt.Println("Parsing Server Hello")

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

	if r.HandshakeHeader.Type != types.HS_TYPE_SERVER_HELLO {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	buf.AddKey("handshake_body_start")

	msg := ServerHelloMessage{}

	msg.Version = binary.BigEndian.Uint16(buf.Next(2))
	copy(msg.Random[:], buf.Next(32))
	msg.SessionIDLength, _ = buf.ReadUint8()

	if msg.SessionIDLength > 0 {
		copy(msg.SessionID, buf.Next(int(msg.SessionIDLength)))
	}

	msg.CipherSuite = binary.BigEndian.Uint16(buf.Next(2))
	msg.CompressionMethod, _ = buf.ReadUint8()

	buf.AddKey("before_extension")
	hs_read_size := buf.ClipSize("handshake_body_start", "before_extension")

	// if has extensions then read the extension
	if hs_read_size < int(r.HandshakeHeader.Length) {
		msg.ExtensionsLength, _ = buf.ReadUint16()
		ext_remain := int(msg.ExtensionsLength)

		for ext_remain > 0 {
			ext_type, _ := buf.ReadUint16()
			ext_len, _ := buf.ReadUint16()
			if ext_len > 0 {
				ext_data := buf.Next(int(ext_len))
				ext := types.Extension{Header: types.ExtensionHeader{Type: ext_type, Length: ext_len}, Data: ext_data}
				msg.Extensions = append(msg.Extensions, ext)
			} else {
				ext := types.Extension{Header: types.ExtensionHeader{Type: ext_type, Length: ext_len}, Data: nil}
				msg.Extensions = append(msg.Extensions, ext)
			}
			ext_remain = ext_remain - types.EXTENSION_HEADER_SIZE - int(ext_len)
		}
	}

	buf.AddKey("end")

	if int(r.HandshakeHeader.Length) != buf.ClipSize("handshake_body_start", "end") {
		return fmt.Errorf("invalid handshake size")
	}

	//multiple handshake message
	if buf.Size() > 0 {
		//fix record header Length
		r.RecordHeader.Length = uint16(buf.ClipSize("handshake_start", "end"))
	}

	buf.ClearKeys()
	r.Message = msg
	return nil
}

func (r ServerHello) SupportExtension(ext_type uint16) bool {
	support := false
	for _, ext := range r.Message.Extensions {
		if ext.Header.Type == ext_type {
			support = true
			break
		}
	}
	return support
}

func (r ServerHello) SupportSessionTicket() bool {
	support := false
	for _, ext := range r.Message.Extensions {
		if ext.Header.Type == types.EXT_TYPE_SESSION_TICKET {
			support = (ext.Header.Length > 0)
			break
		}
	}
	return support
}

func (r ServerHello) String() string {
	out := "\n------------------------- Server Hello ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprint(r.HandshakeHeader)
	out += fmt.Sprint(r.Message)
	return out
}
