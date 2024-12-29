package common

import "crypto/rand"

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
