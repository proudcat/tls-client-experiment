package types

import "fmt"

const (
	PROTOCOL_VERSION_TLS10 uint16 = 0x0301
	PROTOCOL_VERSION_TLS11 uint16 = 0x0302
	PROTOCOL_VERSION_TLS12 uint16 = 0x0303
	PROTOCOL_VERSION_TLS13 uint16 = 0x0304
)

func VersionName(version uint16) string {
	switch version {
	case PROTOCOL_VERSION_TLS10:
		return "TLS 1.0"
	case PROTOCOL_VERSION_TLS11:
		return "TLS 1.1"
	case PROTOCOL_VERSION_TLS12:
		return "TLS 1.2"
	case PROTOCOL_VERSION_TLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}
