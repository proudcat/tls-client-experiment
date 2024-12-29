package common

import (
	"encoding/binary"
	"errors"
)

const (
	BUFFER_GROW_SIZE = 64              // 64 bytes
	MAX_SIZE         = 1024 * 1024 * 8 // max buffer size is 8M
)

type Buffer struct {
	bytes []byte
	w     int // write offset
	r     int // read offset
	keys  map[string]int
}

func NewBuffer() *Buffer {
	return &Buffer{
		bytes: make([]byte, BUFFER_GROW_SIZE),
		w:     0,
		r:     0,
		keys:  make(map[string]int, 0),
	}
}

func (b *Buffer) Append(buf *Buffer) {
	b.Write(buf.PeekAllBytes())
}

func (b *Buffer) AddKey(key string) {
	if _, ok := b.keys[key]; ok {
		panic("key already exists")
	}
	b.keys[key] = b.r
}

func (b *Buffer) ClearKeys() {
	b.keys = make(map[string]int, 0)
}

func (b *Buffer) ClipSize(key1, key2 string) int {
	if _, ok := b.keys[key1]; !ok {
		panic("key not exists")
	}
	if _, ok := b.keys[key2]; !ok {
		panic("key not exists")
	}
	return b.keys[key2] - b.keys[key1]
}

func (b *Buffer) Size() int {
	return b.w - b.r
}

func (b *Buffer) Reset() {
	b.w = 0
	b.r = 0
	b.bytes = make([]byte, BUFFER_GROW_SIZE)
	b.ClearKeys()
}

func (b *Buffer) PeekAllBytes() []byte {
	return b.bytes[b.r:b.w]
}

func (b *Buffer) Drain() []byte {
	out := make([]byte, b.Size())
	copy(out, b.bytes[b.r:b.w])
	b.Reset()
	return out
}

func (b *Buffer) Grow(size int) error {
	if size < BUFFER_GROW_SIZE {
		size = BUFFER_GROW_SIZE
	}

	if len(b.bytes)+size >= MAX_SIZE {
		return errors.New("buffer grows over 128M")
	}

	chunk := make([]byte, size)
	b.bytes = append(b.bytes, chunk...)
	return nil
}

func (b *Buffer) Next(n int) []byte {
	chunk := make([]byte, n)
	copy(chunk, b.bytes[b.r:b.r+n])
	b.r += n
	return chunk
}

func (b *Buffer) Read(chunk []byte) error {

	n := len(chunk)

	if b.Size() < n {
		return errors.New("buffer is not enough")
	}

	copy(chunk, b.bytes[b.r:b.r+n])
	b.r += n
	return nil
}

func (b *Buffer) Write(data []byte) {
	size := len(data)
	if size > len(b.bytes)-b.w {
		if err := b.Grow(size); err != nil {
			panic(err)
		}
	}
	copy(b.bytes[b.w:b.w+size], data)
	b.w += size
}

func (b *Buffer) WriteUint8(data uint8) {
	b.Write([]byte{byte(data)})
}

func (b *Buffer) WriteUint16(data uint16) {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(data))
	b.Write(tmp[:])
}

func (b *Buffer) WriteUint24(data uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(data))
	b.Write(tmp[1:])
}

func (b *Buffer) WriteUint32(data uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, uint32(data))
	b.Write(tmp[:])
}

func (b *Buffer) ReadUint8() (uint8, error) {
	data, err := b.ReadBytes(1)
	return data[0], err
}

func (b *Buffer) ReadUint16() (uint16, error) {
	data, err := b.ReadBytes(2)
	return binary.BigEndian.Uint16(data), err
}

func (b *Buffer) ReadUint24() (uint32, error) {
	data, err := b.ReadBytes(3)
	return binary.BigEndian.Uint32(append([]byte{0}, data...)), err
}

func (b *Buffer) ReadUint32() (uint32, error) {
	data, err := b.ReadBytes(4)
	return binary.BigEndian.Uint32(data), err
}

func (b *Buffer) ReadBytes(n int) ([]byte, error) {

	if b.Size() < n {
		return nil, errors.New("buffer is empty")
	}

	out := make([]byte, n)
	copy(out, b.bytes[b.r:b.r+n])
	b.r += n
	return out, nil
}

func (b *Buffer) PeekInt8() int {
	data := b.Peek(1)
	return int(data[0])
}

func (b *Buffer) PeekInt16() int {
	data := b.Peek(2)
	return int(binary.BigEndian.Uint16(data))
}

func (b *Buffer) PeekInt24() int {
	data := b.Peek(3)
	return int(binary.BigEndian.Uint32(append([]byte{0}, data...)))
}

func (b *Buffer) Peek(n int) []byte {
	return b.bytes[b.r : b.r+n]
}
