package main

import (
	"fmt"
	"testing"
)

func TestDemo(t *testing.T) {
	var padding []byte
	padding = append(padding, 1)
	padding = append(padding, 2)
	padding = append(padding, 3)
	padding = append(padding, 4)
	padding = append(padding, 5)

	fmt.Println(padding[:2])
	fmt.Println(padding)

}

func TestAlice(t *testing.T) {
	padding := [15]byte{15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15}

	fmt.Println(len(padding), padding)

	//32 bytes mac
	//padding
	//padding len

	// additionalData := coreUtils.MakeAdditionalData(seqNum, clientHandshakeFinished.RecordHeader.Type, tlsVersion)
	// encryptedContent, err := cryptoHelpers.Encrypt(clientKey, clientIV, plaintext, additionalData)

	block_plaintext := []byte{}
	block_plaintext = append(block_plaintext, padding[:]...)
	block_plaintext = append(block_plaintext, 15)

	fmt.Println(len(block_plaintext), block_plaintext)
}

func TestBob(t *testing.T) {
	serverName := []byte("abc")
	fmt.Println(serverName)
}

func TestCarol(t *testing.T) {
	content := []byte{1, 2, 3, 4, 5}

	fmt.Println(content[3:5])
}
