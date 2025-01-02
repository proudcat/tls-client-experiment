package types

import (
	"encoding/binary"
)

const (
	MAX_SIZE = 1024 * 1024 // max 1M bytes
)

type ByteBuffer struct {
	bytes  []byte
	offset int // read offset
}

func (b ByteBuffer) Size() int {
	return len(b.bytes)
}

func (b *ByteBuffer) Reset() {
	b.bytes = []byte{}
	b.offset = 0
}

func (b ByteBuffer) Bytes() []byte {
	return b.bytes
}

func (b *ByteBuffer) Write(data []byte) {
	size := len(data)
	if b.Size()+size > MAX_SIZE {
		panic("buffer overflow")
	}
	b.bytes = append(b.bytes, data...)
}

func (b *ByteBuffer) WriteUint8(data uint8) {
	b.Write([]byte{byte(data)})
}

func (b *ByteBuffer) WriteUint16(data uint16) {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(data))
	b.Write(tmp[:])
}

func (b *ByteBuffer) WriteUint24(data uint24) {
	b.Write(data.Bytes())
}

func (b *ByteBuffer) WriteUint32(data uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(data))
	b.Write(tmp[:])
}

func (b *ByteBuffer) Skip(n int) {
	if b.offset+n > b.Size() {
		panic("buffer underflow")
	}
	b.offset += n
}

func (b *ByteBuffer) Next(n int) []byte {
	if b.offset+n > b.Size() {
		panic("buffer underflow")
	}
	chunk := make([]byte, n)
	copy(chunk, b.bytes[b.offset:b.offset+n])
	b.offset += n
	return chunk
}

func (b *ByteBuffer) NextUint8() uint8 {
	data := b.Next(1)
	return data[0]
}

func (b *ByteBuffer) NextUint16() uint16 {
	data := b.Next(2)
	return binary.BigEndian.Uint16(data)
}

func (b *ByteBuffer) NextUint24() uint24 {
	data := b.Next(3)
	var u24 uint24
	u24.FromBytes(data)
	return u24
}

func (b *ByteBuffer) NextUint32() uint32 {
	data := b.Next(4)
	return binary.BigEndian.Uint32(data)
}
