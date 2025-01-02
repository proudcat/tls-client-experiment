package types

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestUint24_Set(t *testing.T) {
	tests := []struct {
		name        string
		val         uint32
		expectPanic bool
	}{
		{"Valid value 0", 0, false},
		{"Valid value 1", 1, false},
		{"Valid value MaxUint24", MaxUint24, false},
		{"Invalid value MaxUint24+1", MaxUint24 + 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectPanic {
						t.Errorf("unexpected panic: %v", r)
					}
				} else {
					if tt.expectPanic {
						t.Errorf("expected panic but did not occur")
					}
				}
			}()

			var u uint24
			u.Set(tt.val)
			if !tt.expectPanic {
				if got := u.Uint32(); got != tt.val {
					t.Errorf("Uint24.Set() = %v, want %v", got, tt.val)
				}
			}
		})
	}
}

func TestUint24_Uint32(t *testing.T) {
	tests := []struct {
		name string
		val  uint32
	}{
		{"Value 0", 0},
		{"Value 1", 1},
		{"Value 255", 255},
		{"Value 256", 256},
		{"Value 65535", 65535},
		{"Value 65536", 65536},
		{"Value MaxUint24", MaxUint24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u uint24
			u.Set(tt.val)
			fmt.Println(tt.val, u.Bytes())
			if got := u.Uint32(); got != tt.val {
				t.Errorf("Uint24.Uint32() = %v, want %v", got, tt.val)
			}
		})
	}
}
func TestUint24_FromBytes(t *testing.T) {
	tests := []struct {
		name        string
		bytes       []byte
		expectPanic bool
		expectedVal uint32
	}{
		{"Valid bytes [0, 0, 0]", []byte{0, 0, 0}, false, 0},
		{"Valid bytes [0, 0, 1]", []byte{0, 0, 1}, false, 1},
		{"Valid bytes [255, 255, 255]", []byte{255, 255, 255}, false, MaxUint24},
		{"Invalid bytes length 2", []byte{0, 0}, true, 0},
		{"Invalid bytes length 4", []byte{0, 0, 0, 0}, true, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.expectPanic {
						t.Errorf("unexpected panic: %v", r)
					}
				} else {
					if tt.expectPanic {
						t.Errorf("expected panic but did not occur")
					}
				}
			}()

			var u uint24
			u.FromBytes(tt.bytes)
			u32 := append([]byte{0}, tt.bytes...)
			fmt.Println(u32, binary.BigEndian.Uint32(u32), u.Uint32())
			if !tt.expectPanic {
				if got := u.Uint32(); got != tt.expectedVal {
					t.Errorf("Uint24.FromBytes() = %v, want %v", got, tt.expectedVal)
				}
			}
		})
	}
}

func TestUint24_Equal(t *testing.T) {
	tests := []struct {
		name string
		u1   uint24
		u2   uint24
		want bool
	}{
		{"Equal values", uint24{[3]uint8{0, 0, 1}}, uint24{[3]uint8{0, 0, 1}}, true},
		{"Different values", uint24{[3]uint8{0, 0, 1}}, uint24{[3]uint8{0, 0, 2}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.u1.Equal(tt.u2); got != tt.want {
				t.Errorf("Uint24.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
