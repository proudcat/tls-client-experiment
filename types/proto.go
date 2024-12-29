package types

import "fmt"

const (
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

func VersionName(version uint16) string {
	switch version {
	case VersionTLS10:
		return "TLS 1.0"
	case VersionTLS11:
		return "TLS 1.1"
	case VersionTLS12:
		return "TLS 1.2"
	case VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

type ContentType uint8

const (
	CHANGE_CIPHER_SPEC ContentType = 20
	ALERT              ContentType = 21
	HANDSHAKE          ContentType = 22
	APPLICATION_DATA   ContentType = 23
)
