package types

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionHeader_FromBytes(t *testing.T) {
	header := ExtensionHeader{}
	data, _ := hex.DecodeString("01140004")
	err := header.FromBytes(data)
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0114), header.Type)
	assert.Equal(t, uint16(0x0004), header.Length)
}

func TestExtensionHeader_ToBytes(t *testing.T) {
	header := ExtensionHeader{
		Type:   0x0000,
		Length: 0x0004,
	}
	expected, _ := hex.DecodeString("00000004")
	assert.Equal(t, expected, header.ToBytes())
}

func TestExtension_FromBytes(t *testing.T) {
	ext := Extension{}
	data, _ := hex.DecodeString("0000000401020304")
	err := ext.FromBytes(data)
	data[0] = 0x11
	data[1] = 0x22
	assert.NoError(t, err)
	assert.Equal(t, uint16(0x0000), ext.Header.Type)
	assert.Equal(t, uint16(0x0004), ext.Header.Length)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, ext.Data)
}

func TestExtension_ToBytes(t *testing.T) {
	ext := Extension{
		Header: ExtensionHeader{
			Type:   0x0000,
			Length: 0x0004,
		},
		Data: []byte{0x01, 0x02, 0x03, 0x04},
	}
	expected, _ := hex.DecodeString("0000000401020304")
	assert.Equal(t, expected, ext.ToBytes())

	fmt.Println(length(nil))
}

func length(data []byte) int {
	return len(data)
}
