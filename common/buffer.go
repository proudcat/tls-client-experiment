package common

import (
	"encoding/binary"
	"fmt"
)

const (
	MAX_SIZE uint32 = 1024 * 1024 * 128 // max 1M bytes
)

type Buffer struct {
	bytes  []byte
	offset uint32 // read offset
}

func (b Buffer) Size() uint32 {
	return uint32(len(b.bytes) - int(b.offset))
}

func (b Buffer) Offset() uint32 {
	return b.offset
}

func (b *Buffer) Reset() {
	b.bytes = []byte{}
	b.offset = 0
}

func (b Buffer) Bytes() []byte {
	return b.bytes[b.offset:]
}

func (b *Buffer) Drain() []byte {
	b.bytes = b.bytes[b.offset:]
	b.offset = 0
	return b.bytes
}

func (b *Buffer) Shrink() {
	b.bytes = b.bytes[b.offset:]
	b.offset = 0
}

func (b *Buffer) Write(data []byte) {
	size := uint32(len(data))
	if b.Size()+size > MAX_SIZE {
		fmt.Println(b.Size(), size, MAX_SIZE)
		panic("buffer overflow")
	}
	b.bytes = append(b.bytes, data...)
}

func (b *Buffer) WriteUint8(data uint8) {
	b.Write([]byte{byte(data)})
}

func (b *Buffer) WriteUint16(data uint16) {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(data))
	b.Write(tmp[:])
}

func (b *Buffer) WriteUint24(data Uint24) {
	b.Write(data.Bytes())
}

func (b *Buffer) WriteUint32(data uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(data))
	b.Write(tmp[:])
}

func (b *Buffer) Skip(n uint32) {
	if n > b.Size() {
		b.Reset()
		return
	}
	b.offset += n
}

func (b *Buffer) Next(n uint32) []byte {
	if n > b.Size() {
		panic("buffer underflow!")
	}
	chunk := make([]byte, n)
	copy(chunk, b.bytes[b.offset:b.offset+n])
	b.offset += n
	return chunk
}

func (b *Buffer) NextUint8() uint8 {
	data := b.Next(1)
	return data[0]
}

func (b *Buffer) NextUint16() uint16 {
	data := b.Next(2)
	return binary.BigEndian.Uint16(data)
}

func (b *Buffer) NextUint24() Uint24 {
	data := b.Next(3)
	var u24 Uint24
	u24.FromBytes(data)
	return u24
}

func (b *Buffer) NextUint32() uint32 {
	data := b.Next(4)
	return binary.BigEndian.Uint32(data)
}
