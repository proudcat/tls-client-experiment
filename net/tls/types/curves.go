package types

import (
	"crypto/ecdh"
)

type CurveInfo struct {
	Code  uint16 //[2]byte
	Name  string
	Curve ecdh.Curve
}

const (
	SECP256R1 uint16 = 0x0017
	SECP384R1 uint16 = 0x0018
	X25519    uint16 = 0x001d
)

var Curves = map[uint16]CurveInfo{
	SECP256R1: {
		Code:  SECP256R1, //[2]byte{0x00, 0x17},
		Name:  "secp256r1",
		Curve: ecdh.P256(),
	},
	SECP384R1: {
		Code:  SECP384R1, //[2]byte{0x00, 0x18},
		Name:  "secp384r1",
		Curve: ecdh.P384(),
	},
	X25519: {
		Code:  X25519, //[2]byte{0x00, 0x1d},
		Name:  "X25519",
		Curve: ecdh.X25519(), //unsupported by elliptic package
	},
}

func GetCurveName(code uint16) string {
	return Curves[code].Name
}
