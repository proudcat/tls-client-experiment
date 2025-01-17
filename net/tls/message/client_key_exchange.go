package message

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/proudcat/tls-client-experiment/buildin"
	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type ClientKeyExchangeMessage struct {
	PublicKeyLength byte
	PublicKey       []byte
}

func (m ClientKeyExchangeMessage) Size() uint32 {
	return uint32(m.PublicKeyLength + 1)
}

func (m ClientKeyExchangeMessage) ToBytes() []byte {
	buf := buildin.Buffer{}
	buf.WriteUint8(m.PublicKeyLength)
	buf.Write(m.PublicKey)
	return buf.Bytes()
}

type ClientKeyExchange struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	PrivateKey      []byte
	Message         ClientKeyExchangeMessage
}

func NewClientKeyExchange(tls_version uint16, curve ecdh.Curve) *ClientKeyExchange {

	sk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic("Failed to generate private key")
	}

	pk := sk.PublicKey().Bytes()

	msg := ClientKeyExchangeMessage{
		PublicKeyLength: byte(len(pk)),
		PublicKey:       pk,
	}

	record := &ClientKeyExchange{
		RecordHeader: types.RecordHeader{
			ContentType: types.RECORD_TYPE_HANDSHAKE,
			Version:     tls_version,
			Length:      uint16(msg.Size() + types.HANDSHAKE_HEADER_SIZE),
		},
		HandshakeHeader: types.HandshakeHeader{
			Type:   types.HS_TYPE_CLIENT_KEY_EXCHANGE,
			Length: buildin.NewUint24(msg.Size()),
		},
		PrivateKey: sk.Bytes(),
		Message:    msg,
	}
	return record
}

func (r ClientKeyExchange) ToBytes() []byte {
	buf := buildin.Buffer{}
	buf.Write(r.RecordHeader.ToBytes())
	buf.Write(r.HandshakeHeader.ToBytes())
	buf.Write(r.Message.ToBytes())
	return buf.Bytes()
}

func (r ClientKeyExchange) String() string {
	out := "\n------------------------- Client Key Exchange ------------------------- \n"
	out += fmt.Sprint(r.RecordHeader)
	out += fmt.Sprint(r.HandshakeHeader)
	out += fmt.Sprintf("PublicKeyLength.....: %d\n", r.Message.PublicKeyLength)
	out += fmt.Sprintf("Public Key..........: %x\n", r.Message.PublicKey)
	out += fmt.Sprintf("Private Key.........: %x\n", r.PrivateKey)
	return out
}
