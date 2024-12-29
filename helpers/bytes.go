package helpers

import (
	"encoding/binary"
)

func Uint16ToBytes(i uint16) [2]byte {
	byteArray := make([]byte, 2)
	binary.BigEndian.PutUint16(byteArray, uint16(i))
	var tmp [2]byte
	copy(tmp[:], byteArray)
	return tmp
}

func Uint24ToBytes(i uint32) [3]byte {
	byteArray := make([]byte, 4)
	binary.BigEndian.PutUint32(byteArray, uint32(i))
	var tmp [3]byte
	copy(tmp[:], byteArray[1:])
	return tmp
}

func Uint32ToBytes(i uint32) [4]byte {
	byteArray := make([]byte, 4)
	binary.BigEndian.PutUint32(byteArray, uint32(i))
	var tmp [4]byte
	copy(tmp[:], byteArray)
	return tmp
}

func Bytes2Uint16(byteArray [2]byte) uint16 {
	return binary.BigEndian.Uint16(byteArray[:])
}

func Bytes2Uint24(byteArray [3]byte) uint32 {
	return binary.BigEndian.Uint32(append([]byte{0}, byteArray[:]...))
}

func Bytes2Uint32(byteArray [4]byte) int {
	return int(binary.BigEndian.Uint32(byteArray[:]))
}
