package helpers

import (
	"crypto/rand"
	"hash"
)

func Random32() [32]byte {
	r := make([]byte, 32)
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}
	var tmp [32]byte
	copy(tmp[:], r)
	return tmp
}

// Apply hashing function based on given name to hash message
func HashByteArray(hashAlgorithm func() hash.Hash, byteArray []byte) []byte {
	hashFunc := hashAlgorithm()
	hashFunc.Reset()
	hashFunc.Write(byteArray)
	hashedOutput := hashFunc.Sum(nil)
	return hashedOutput
}
