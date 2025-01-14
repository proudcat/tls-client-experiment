package message

import (
	"fmt"
	"strconv"

	"github.com/proudcat/tls-client-experiment/net/tls/types"
)

type AlertError struct {
	RecordHeader types.RecordHeader
	Level        byte
	Detail       byte
}

func (e *AlertError) FromBytes(bytes []byte) {
	e.RecordHeader.FromBytes(bytes[:types.RECORD_HEADER_SIZE])
	e.Level = bytes[types.RECORD_HEADER_SIZE]
	e.Detail = bytes[types.RECORD_HEADER_SIZE+1]
}

func (e AlertError) String() string {
	out := "\n\n >>>>>>>>>>>>>>>> ALERT  <<<<<<<<<<<<<<<< \n"
	out += fmt.Sprintf(" %s", e.RecordHeader)
	out += fmt.Sprintf(" Level: %s(%d)\n", alertLevelText[e.Level], e.Level)
	out += fmt.Sprintf(" Detail: %s\n", alert(e.Detail))
	return out
}

type alert uint8

const (
	// alert level
	ALERT_LEVEL_WARNING byte = 1 // warning
	ALERT_LEVEL_ERROR   byte = 2 // fatal
)

var alertLevelText = map[byte]string{
	ALERT_LEVEL_WARNING: "Warning",
	ALERT_LEVEL_ERROR:   "Fatal",
}

const (
	ALERT_CLOSE_NOTIFY                    alert = 0
	ALERT_UNEXPECTED_MESSAGE              alert = 10
	ALERT_BAD_RECORD_MAC                  alert = 20
	ALERT_DECRYPTION_FAILED               alert = 21
	ALERT_RECORD_OVERFLOW                 alert = 22
	ALERT_DECOMPRESSION_FAILURE           alert = 30
	ALERT_HANDSHAKE_FAILURE               alert = 40
	ALERT_BAD_CERTIFICATE                 alert = 42
	ALERT_UNSUPPORTED_CERTIFICATE         alert = 43
	ALERT_CERTIFICATE_REVOKED             alert = 44
	ALERT_CERTIFICATE_EXPIRED             alert = 45
	ALERT_CERTIFICATE_UNKNOWN             alert = 46
	ALERT_ILLEGAL_PARAMETER               alert = 47
	ALERT_UNKNOWN_CA                      alert = 48
	ALERT_ACCESS_DENIED                   alert = 49
	ALERT_DECODE_ERROR                    alert = 50
	ALERT_DECRYPT_ERROR                   alert = 51
	ALERT_EXPORT_RESTRICTION              alert = 60
	ALERT_PROTOCOL_VERSION                alert = 70
	ALERT_INSUFFICIENT_SECURITY           alert = 71
	ALERT_INTERNAL_ERROR                  alert = 80
	ALERT_INAPPROPRIATE_FALLBACK          alert = 86
	ALERT_USER_CANCELED                   alert = 90
	ALERT_NO_RENEGOTIATION                alert = 100
	ALERT_MISSING_EXTENSION               alert = 109
	ALERT_UNSUPPORTED_EXTENSION           alert = 110
	ALERT_CERTIFICATE_UNOBTAINABLE        alert = 111
	ALERT_UNRECOGNIZED_NAME               alert = 112
	ALERT_BAD_CERTIFICATE_STATUS_RESPONSE alert = 113
	ALERT_BAD_CERTIFICATE_HASH_VALUE      alert = 114
	ALERT_UNKNOWN_PSK_IDENTITY            alert = 115
	ALERT_CERTIFICATE_REQUIRED            alert = 116
	ALERT_NO_APPLICATION_PROTOCOL         alert = 120
	ALERT_ECH_REQUIRED                    alert = 121
)

var alertText = map[alert]string{
	ALERT_CLOSE_NOTIFY:                    "close notify",
	ALERT_UNEXPECTED_MESSAGE:              "unexpected message",
	ALERT_BAD_RECORD_MAC:                  "bad record MAC",
	ALERT_DECRYPTION_FAILED:               "decryption failed",
	ALERT_RECORD_OVERFLOW:                 "record overflow",
	ALERT_DECOMPRESSION_FAILURE:           "decompression failure",
	ALERT_HANDSHAKE_FAILURE:               "handshake failure",
	ALERT_BAD_CERTIFICATE:                 "bad certificate",
	ALERT_UNSUPPORTED_CERTIFICATE:         "unsupported certificate",
	ALERT_CERTIFICATE_REVOKED:             "revoked certificate",
	ALERT_CERTIFICATE_EXPIRED:             "expired certificate",
	ALERT_CERTIFICATE_UNKNOWN:             "unknown certificate",
	ALERT_ILLEGAL_PARAMETER:               "illegal parameter",
	ALERT_UNKNOWN_CA:                      "unknown certificate authority",
	ALERT_ACCESS_DENIED:                   "access denied",
	ALERT_DECODE_ERROR:                    "error decoding message",
	ALERT_DECRYPT_ERROR:                   "error decrypting message",
	ALERT_EXPORT_RESTRICTION:              "export restriction",
	ALERT_PROTOCOL_VERSION:                "protocol version not supported",
	ALERT_INSUFFICIENT_SECURITY:           "insufficient security level",
	ALERT_INTERNAL_ERROR:                  "internal error",
	ALERT_INAPPROPRIATE_FALLBACK:          "inappropriate fallback",
	ALERT_USER_CANCELED:                   "user canceled",
	ALERT_NO_RENEGOTIATION:                "no renegotiation",
	ALERT_MISSING_EXTENSION:               "missing extension",
	ALERT_UNSUPPORTED_EXTENSION:           "unsupported extension",
	ALERT_CERTIFICATE_UNOBTAINABLE:        "certificate unobtainable",
	ALERT_UNRECOGNIZED_NAME:               "unrecognized name",
	ALERT_BAD_CERTIFICATE_STATUS_RESPONSE: "bad certificate status response",
	ALERT_BAD_CERTIFICATE_HASH_VALUE:      "bad certificate hash value",
	ALERT_UNKNOWN_PSK_IDENTITY:            "unknown PSK identity",
	ALERT_CERTIFICATE_REQUIRED:            "certificate required",
	ALERT_NO_APPLICATION_PROTOCOL:         "no application protocol",
	ALERT_ECH_REQUIRED:                    "encrypted client hello required",
}

func (e alert) String() string {
	s, ok := alertText[e]
	if ok {
		return s
	}
	return "alert(" + strconv.Itoa(int(e)) + ")"
}

func (e alert) Error() string {
	return e.String()
}
