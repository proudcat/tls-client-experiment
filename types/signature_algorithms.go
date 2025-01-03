package types

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"hash"
)

type SignatureAlgorithmInfo struct {
	Code             uint16 //[2]byte
	HashingAlgorithm func() hash.Hash
	HashCode         crypto.Hash
	Type             tls.SignatureScheme
}

const (
	rsa_pkcs1_sha256       uint16 = 0x0401
	ecdsa_secp256r1_sha256 uint16 = 0x0403
	rsa_pkcs1_sha1         uint16 = 0x0201
)

var SignatureAlgorithms = map[uint16]SignatureAlgorithmInfo{
	//"rsa_pkcs1_sha512":                                     {0x06, 0x01},
	//"Signature Algorithm: SHA512 DSA (0x0602)":             {0x06, 0x02},
	//"Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)": {0x06, 0x03},
	//"rsa_pkcs1_sha384":                                     {0x05, 0x01},
	//"Signature Algorithm: SHA384 DSA (0x0502)":             {0x05, 0x02},
	//"ecdsa_secp384r1_sha384":                               {0x05, 0x03},
	// "rsa_pkcs1_sha256":                                    {0x04, 0x01},
	rsa_pkcs1_sha256: {
		Code:             rsa_pkcs1_sha256, //[2]byte{0x04, 0x01},
		HashingAlgorithm: sha256.New,
		HashCode:         crypto.SHA256,
		Type:             tls.PKCS1WithSHA256,
	},
	//"Signature Algorithm: SHA256 DSA (0x0402)":             {0x04, 0x02},
	ecdsa_secp256r1_sha256: {
		Code:             ecdsa_secp256r1_sha256, //[2]byte{0x04, 0x03},
		HashingAlgorithm: sha256.New,
		HashCode:         crypto.SHA256,
		Type:             tls.ECDSAWithP256AndSHA256,
	},
	//"Signature Algorithm: SHA224 RSA (0x0301)":             {0x03, 0x01},
	//"Signature Algorithm: SHA224 DSA (0x0302)":             {0x03, 0x02},
	//"Signature Algorithm: SHA224 ECDSA (0x0303)":           {0x03, 0x03},
	// rsa_pkcs1_sha1: {
	// 	Code:             rsa_pkcs1_sha1, //[2]byte{0x02, 0x01},
	// 	HashingAlgorithm: sha1.New,
	// 	HashCode:         crypto.SHA1,
	// 	Type:             tls.PKCS1WithSHA1,
	// },
	//"Signature Algorithm: SHA1 DSA (0x0202)":               {0x02, 0x02},
	//"Signature Algorithm: ecdsa_sha1 (0x0203)":             {0x02, 0x03},
	//"rsa_pss_rsae_sha256":                                  {0x08, 0x04},
	//"rsa_pss_rsae_sha384":                                  {0x08, 0x05},
	//"rsa_pss_rsae_sha512":                                  {0x08, 0x06},
	//"ed25519":                                              {0x08, 0x07},
	//"ed448":                                                {0x08, 0x08},
	//"rsa_pss_pss_sha256":                                   {0x08, 0x09},
	//"rsa_pss_pss_sha384":                                   {0x08, 0x0a},
	//"rsa_pss_pss_sha512":                                   {0x08, 0x0b},
}
