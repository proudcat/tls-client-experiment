package zkp

import (
	"encoding/binary"
	"slices"
	"testing"
)

func TestBuffer_Size(t *testing.T) {
	b := Buffer{}
	if b.Size() != 0 {
		t.Errorf("expected size 0, got %d", b.Size())
	}
	b.Write([]byte{1, 2, 3})
	if b.Size() != 3 {
		t.Errorf("expected size 3, got %d", b.Size())
	}

	b.Next(2)
	if b.Size() != 1 {
		t.Errorf("expected size 1, got %d", b.Size())
	}
}

func TestBuffer_Reset(t *testing.T) {
	b := Buffer{}
	b.Write([]byte{1, 2, 3})
	b.Reset()
	if b.Size() != 0 {
		t.Errorf("expected size 0 after reset, got %d", b.Size())
	}
	if b.offset != 0 {
		t.Errorf("expected offset 0 after reset, got %d", b.offset)
	}
}

func TestBuffer_Write(t *testing.T) {
	b := Buffer{}
	data := []byte{1, 2, 3}
	b.Write(data)
	if b.Size() != uint32(len(data)) {
		t.Errorf("expected size %d, got %d", len(data), b.Size())
	}
	if b.offset != uint32(len(data)) {
		t.Errorf("expected offset %d, got %d", len(data), b.offset)
	}

	if !slices.Equal(data, b.Bytes()) {
		t.Errorf("expected data %v, got %v", data, b.Bytes())
	}
}

func TestBuffer_WriteUint8(t *testing.T) {
	b := Buffer{}
	b.WriteUint8(255)
	if b.Size() != 1 {
		t.Errorf("expected size 1, got %d", b.Size())
	}
	if b.bytes[0] != 255 {
		t.Errorf("expected byte 255, got %d", b.bytes[0])
	}
}

func TestBuffer_WriteUint16(t *testing.T) {
	b := Buffer{}
	b.WriteUint16(65535)
	if b.Size() != 2 {
		t.Errorf("expected size 2, got %d", b.Size())
	}
	expected := make([]byte, 2)
	binary.BigEndian.PutUint16(expected, 65535)
	if !slices.Equal(b.bytes, expected) {
		t.Errorf("expected bytes %v, got %v", expected, b.bytes)
	}
	for i, v := range expected {
		if b.bytes[i] != v {
			t.Errorf("expected byte %d, got %d", v, b.bytes[i])
		}
	}
}

func TestBuffer_WriteUint24(t *testing.T) {
	b := Buffer{}
	data := []byte{254, 255, 255}
	var want Uint24
	want.FromBytes(data)
	b.WriteUint24(want)
	if b.Size() != 3 {
		t.Errorf("expected size 3, got %d", b.Size())
	}

	got := b.NextUint24()
	if got != want {
		t.Errorf("expected %d, got %d", want, got)
	}

}

func TestBuffer_WriteUint32(t *testing.T) {
	b := Buffer{}
	b.WriteUint32(4294967295)
	if b.Size() != 4 {
		t.Errorf("expected size 4, got %d", b.Size())
	}
	expected := make([]byte, 4)
	binary.BigEndian.PutUint32(expected, 4294967295)
	for i, v := range expected {
		if b.bytes[i] != v {
			t.Errorf("expected byte %d, got %d", v, b.bytes[i])
		}
	}
}

func TestBuffer_Next(t *testing.T) {
	b := Buffer{}
	data := []byte{1, 2, 3, 4}
	b.Write(data)
	chunk := b.Next(2)
	if len(chunk) != 2 {
		t.Errorf("expected chunk size 2, got %d", len(chunk))
	}
	if chunk[0] != 1 || chunk[1] != 2 {
		t.Errorf("expected chunk [1 2], got %v", chunk)
	}
	if b.offset != 2 {
		t.Errorf("expected offset 2, got %d", b.offset)
	}
}

func TestBuffer_NextUint8(t *testing.T) {
	b := Buffer{}
	b.Write([]byte{255})
	val := b.NextUint8()
	if val != 255 {
		t.Errorf("expected 255, got %d", val)
	}
}

func TestBuffer_NextUint16(t *testing.T) {
	b := Buffer{}
	b.WriteUint16(65535)
	val := b.NextUint16()
	if val != 65535 {
		t.Errorf("expected 65535, got %d", val)
	}
}

func TestBuffer_NextUint32(t *testing.T) {
	b := Buffer{}
	b.WriteUint32(4294967295)
	val := b.NextUint32()
	if val != 4294967295 {
		t.Errorf("expected 4294967295, got %d", val)
	}
}

func TestBuffer(t *testing.T) {
	b := Buffer{}
	b.Write([]byte{1, 2, 3})
	b.WriteUint16(65535)

	b.WriteUint32(4294967295)
	if b.Size() != 9 {
		t.Errorf("expected size 9, got %d", b.Size())
	}
	if b.offset != 0 {
		t.Errorf("expected offset 0, got %d", b.offset)
	}

	data := b.Next(3)
	if !slices.Equal(data, []byte{1, 2, 3}) {
		t.Errorf("expected data [1 2 3], got %v", data)
	}
	if b.offset != 3 {
		t.Errorf("expected offset 3, got %d", b.offset)
	}

	u16 := b.NextUint16()
	if u16 != 65535 {
		t.Errorf("expected 65535, got %d", u16)
	}

	u32 := b.NextUint32()
	if u32 != 4294967295 {
		t.Errorf("expected 4294967295, got %d", u32)
	}

}
func TestBuffer_Bytes(t *testing.T) {
	b := Buffer{}
	data := []byte{1, 2, 3, 4}
	b.Write(data)
	b.Next(2)
	bytes := b.Bytes()
	if !slices.Equal(bytes, []byte{3, 4}) {
		t.Errorf("expected bytes [3 4], got %v", bytes)
	}
}

func TestBuffer_Drain(t *testing.T) {
	b := Buffer{}
	data := []byte{1, 2, 3, 4}
	b.Write(data)
	b.Next(2)
	drained := b.Drain()
	if !slices.Equal(drained, []byte{3, 4}) {
		t.Errorf("expected drained bytes [3 4], got %v", drained)
	}
	if b.Size() != 2 {
		t.Errorf("expected size 2 after drain, got %d", b.Size())
	}
	if b.offset != 0 {
		t.Errorf("expected offset 0 after drain, got %d", b.offset)
	}
}

func TestBuffer_Shrink(t *testing.T) {
	b := Buffer{}
	data := []byte{1, 2, 3, 4, 5}
	b.Write(data)
	b.Next(2)
	b.Shrink()
	if b.Size() != 3 {
		t.Errorf("expected size 2 after shrink, got %d", b.Size())
	}
	if b.offset != 0 {
		t.Errorf("expected offset 0 after shrink, got %d", b.offset)
	}
	if !slices.Equal(b.Bytes(), []byte{3, 4, 5}) {
		t.Errorf("expected bytes [3 4] after shrink, got %v", b.Bytes())
	}
}
