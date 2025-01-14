package buildin

import "fmt"

// big endian uint24

const MaxUint24 = 1<<24 - 1

type Uint24 struct {
	v [3]uint8
}

func NewUint24(val uint32) Uint24 {
	var u Uint24
	u.Set(val)
	return u
}

func (u Uint24) Equal(a Uint24) bool {
	return u.v[0] == a.v[0] && u.v[1] == a.v[1] && u.v[2] == a.v[2]
}

func (u *Uint24) FromBytes(b []byte) {
	if len(b) != 3 {
		panic("invalid byte length")
	}
	copy(u.v[:], b)
}

func (u Uint24) Bytes() []byte {
	return u.v[:]
}

func (u *Uint24) Set(val uint32) {
	if val > MaxUint24 {
		panic("cannot set Uint24 larger than uint24.MaxUint24")
	}
	u.v[2] = uint8(val & 0xFF)
	u.v[1] = uint8((val >> 8) & 0xFF)
	u.v[0] = uint8((val >> 16) & 0xFF)
}

func (u Uint24) Uint32() uint32 {
	return uint32(u.v[2]) | uint32(u.v[1])<<8 | uint32(u.v[0])<<16
}

func (u Uint24) String() string {
	return fmt.Sprintf("%d", u.Uint32())
}
