package helpers

import (
	"crypto/elliptic"
)

type SecurityParameters struct {
	ServerKeyExchangePublicKey  []byte
	ClientKeyExchangePrivateKey []byte
	Curve                       elliptic.Curve
	PreMasterSecret             []byte //32 bytes
	MasterSecret                []byte //48 bytes
	ClientRandom                [32]byte
	ServerRandom                [32]byte
	ClientMAC                   []byte
	ServerMAC                   []byte
	ClientKey                   []byte
	ServerKey                   []byte
	ClientIV                    []byte
	ServerIV                    []byte
}
