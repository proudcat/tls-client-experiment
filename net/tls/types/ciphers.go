package types

import (
	"crypto/sha256"
	"hash"
)

const (
	GREASE                                  uint16 = 0x4a4a
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
)

type CipherSuiteInfo struct {
	ID               uint16
	Name             string
	HashingAlgorithm func() hash.Hash
}

var CipherSuites = map[uint16]CipherSuiteInfo{
	GREASE: {
		ID:               GREASE,
		Name:             "GREASE",
		HashingAlgorithm: sha256.New,
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		ID:               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Name:             "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		HashingAlgorithm: sha256.New,
	},
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		ID:               TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Name:             "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		HashingAlgorithm: sha256.New,
	},
}
