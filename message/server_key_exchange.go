package message

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/types"
)

type Signature struct {
	Algorithm uint16 //[2]byte
	Length    uint16 //[2]byte
	Content   []byte
}

func (signature Signature) String() string {
	out := fmt.Sprintln("Signature")
	out += fmt.Sprintf("  Algorithm.....: %#04x\n", signature.Algorithm)
	out += fmt.Sprintf("  Length........: %#04x\n", signature.Length)
	out += fmt.Sprintf("  Signature.....: %x\n", signature.Content)
	return out
}

type ServerKeyExchange struct {
	RecordHeader    types.RecordHeader
	HandshakeHeader types.HandshakeHeader
	Curve           byte
	CurveID         uint16 //[2]byte
	PublicKeyLength byte
	PublicKey       []byte
	Signature       Signature
}

func (r *ServerKeyExchange) FromBuffer(buf *common.Buffer) error {

	fmt.Println("Parsing Server Key Exchange")

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

	if r.HandshakeHeader.Type != types.HS_TYPE_SERVER_KEY_EXCHANGE {
		return fmt.Errorf("invalid handshake type %d", r.HandshakeHeader.Type)
	}

	buf.AddKey("payload_start")

	r.Curve = buf.Next(1)[0]

	r.CurveID = binary.BigEndian.Uint16(buf.Next(2))

	r.PublicKeyLength = buf.Next(1)[0]

	r.PublicKey = buf.Next(int(r.PublicKeyLength))

	signature := Signature{}
	signature.Algorithm = binary.BigEndian.Uint16(buf.Next(2))
	signature.Length = binary.BigEndian.Uint16(buf.Next(2))
	signature.Content = buf.Next(int(signature.Length))

	buf.AddKey("end")

	if int(r.HandshakeHeader.Length) != buf.ClipSize("payload_start", "end") {
		return fmt.Errorf("invalid handshake size")
	}

	//we need fix record length when multiple handshake message
	r.RecordHeader.Length = uint16(buf.ClipSize("handshake_start", "end"))

	r.Signature = signature

	buf.ClearKeys()
	return nil
}

func (serverKeyExchange ServerKeyExchange) VerifySignature(securityParams helpers.SecurityParameters, pubKey any) bool {
	buf := common.NewBuffer()
	buf.Write(securityParams.ClientRandom[:])
	buf.Write(securityParams.ServerRandom[:])
	buf.WriteUint8(serverKeyExchange.Curve)
	buf.WriteUint16(serverKeyExchange.CurveID)
	buf.WriteUint8(serverKeyExchange.PublicKeyLength)
	buf.Write(serverKeyExchange.PublicKey)

	algorithm, ok := types.SignatureAlgorithms[serverKeyExchange.Signature.Algorithm]
	if !ok {
		panic(fmt.Sprintf("Unknown signature algorithm %#04x", serverKeyExchange.Signature.Algorithm))
	}

	hashed := helpers.HashByteArray(algorithm.HashingAlgorithm, buf.Drain())

	switch algorithm.Type {
	case tls.ECDSAWithP256AndSHA256:
		success := ecdsa.VerifyASN1(pubKey.(*ecdsa.PublicKey), hashed[:], serverKeyExchange.Signature.Content)
		return success
	case tls.PKCS1WithSHA256:
		err := rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), algorithm.HashCode, hashed[:], serverKeyExchange.Signature.Content)
		if err != nil {
			fmt.Println(err)
			return false
		}
		return true
	default:
		return false
	}
}

func (serverKeyExchange ServerKeyExchange) String() string {
	out := "\n------------------------- Server Key Exchange ------------------------- \n"
	out += fmt.Sprint(serverKeyExchange.RecordHeader)
	out += fmt.Sprint(serverKeyExchange.HandshakeHeader)
	out += fmt.Sprintf("  Curve Type.........: %6x\n", serverKeyExchange.Curve)
	out += fmt.Sprintf("  Curve..............: %6x - %s\n", serverKeyExchange.CurveID, types.Curves[serverKeyExchange.CurveID].Name)
	out += fmt.Sprintf("  Public Key length..: %6x\n", serverKeyExchange.PublicKeyLength)
	out += fmt.Sprintf("  Public Key.........: %6x\n", serverKeyExchange.PublicKey)
	out += fmt.Sprint(serverKeyExchange.Signature)
	return out
}
