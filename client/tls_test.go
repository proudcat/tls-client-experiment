package client

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/message"
)

func TestBuffer_Size(t *testing.T) {

	// cipher_suite := uint16(0xc02b)  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	hashing_algorithm := sha256.New // SHA256
	tls_version := uint16(0x0303)   // TLS 1.2
	// curve_id := uint16(0x0017)      // secp256r1
	curve := elliptic.P256()

	sk := []byte{142, 192, 45, 204, 206, 11, 84, 122, 237, 169, 200, 177, 238, 68, 179, 116, 123, 9, 113, 126, 118, 27, 3, 159, 132, 30, 233, 253, 142, 39, 115, 24}
	// pk := []byte{4, 138, 47, 193, 98, 116, 249, 8, 130, 39, 78, 124, 103, 112, 21, 11, 251, 24, 51, 156, 78, 190, 163, 150, 123, 148, 42, 7, 211, 52, 142, 167, 119, 6, 191, 191, 153, 221, 247, 217, 205, 102, 109, 102, 52, 47, 203, 204, 54, 187, 218, 246, 79, 108, 152, 20, 227, 100, 240, 153, 242, 109, 212, 28, 178}

	security_params := helpers.SecurityParameters{
		ServerKeyExchangePublicKey:  []byte{0x4, 0xe3, 0x48, 0x6c, 0x7d, 0xa1, 0xab, 0x87, 0x89, 0xfe, 0x3e, 0x66, 0x73, 0xa0, 0x8d, 0x73, 0x6, 0x98, 0xdb, 0xe9, 0x9b, 0x2f, 0xfd, 0x5e, 0x63, 0x85, 0xdb, 0x3b, 0x8c, 0xff, 0x49, 0x75, 0xd6, 0xb4, 0x96, 0x3, 0x93, 0x32, 0x2e, 0x3c, 0x14, 0xbd, 0xf7, 0x18, 0x7c, 0x86, 0xf8, 0x13, 0xa8, 0xb3, 0x8a, 0xab, 0xb9, 0xf5, 0xf4, 0x2, 0xde, 0x87, 0x54, 0xb0, 0xd9, 0x4b, 0x31, 0x94, 0xa3},
		ClientKeyExchangePrivateKey: sk,
		Curve:                       curve,
		ClientRandom:                [32]uint8{28, 95, 65, 116, 56, 222, 51, 151, 239, 43, 212, 212, 135, 149, 24, 204, 41, 113, 34, 164, 216, 169, 44, 254, 137, 200, 118, 136, 11, 150, 121, 250},
		ServerRandom:                [32]uint8{207, 58, 83, 172, 139, 215, 175, 107, 145, 125, 63, 231, 74, 236, 54, 165, 218, 116, 222, 90, 209, 234, 227, 85, 137, 190, 67, 69, 8, 161, 3, 214},
	}

	// messages := zkp.Buffer{}
	// messages.Write([]byte("abcdefghijklmnopqrstuvwxyz"))

	messages := []byte("abcdefghijklmnopqrstuvwxyz")

	/*********** client finished ***********/
	hash_messages := helpers.HashByteArray(hashing_algorithm, messages)
	verify_data := helpers.MakeClientVerifyData(&security_params, hash_messages)
	if verify_data == nil || len(verify_data) != 12 {
		panic("could not create VerifyData")
	}

	client_finished, err := message.MakeClientFinished(&security_params, verify_data, tls_version, 0)

	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", security_params)

	fmt.Println("==========================================")

	fmt.Println("hash_messages", hash_messages)

	fmt.Println("------------------------------------------")

	fmt.Println("verify_data", verify_data)

	fmt.Println("******************************************")

	fmt.Println("client_finished", client_finished)

}
