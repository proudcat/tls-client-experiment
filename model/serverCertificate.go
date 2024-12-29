package model

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/proudcat/tls-client-experiment/certificate"
	"github.com/proudcat/tls-client-experiment/constants"
	"github.com/proudcat/tls-client-experiment/helpers"
)

type Certificate struct {
	Length      [3]byte
	Content     []byte
	Certificate *x509.Certificate
}

func (certificate Certificate) String() string {
	out := "  Certificate\n"
	out += fmt.Sprintf("    Certificate Length.: %x\n", certificate.Length)
	out += fmt.Sprintf("    Certificate........: %x\n", certificate.Content)
	out += fmt.Sprintf("    Certificate Public Key........: %x\n", certificate.Certificate.PublicKey)
	out += fmt.Sprintf("    Certificate Issuer............: %s\n", certificate.Certificate.Issuer)
	out += fmt.Sprintf("    Signature Algorithm...........: %s\n", certificate.Certificate.SignatureAlgorithm)
	return out
}

func (certificate *Certificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Length             uint32 `json:"Length"`
		Content            string `json:"Content"`
		Issuer             string `json:"Issuer"`
		SignatureAlgorithm string `json:"SignatureAlgorithm"`
	}{
		Length:             helpers.Convert3ByteArrayToUInt32(certificate.Length),
		Content:            hex.EncodeToString(certificate.Content),
		Issuer:             certificate.Certificate.Issuer.String(),
		SignatureAlgorithm: certificate.Certificate.SignatureAlgorithm.String(),
	})
}

type ServerCertificate struct {
	RecordHeader      RecordHeader
	HandshakeHeader   HandshakeHeader
	CertificateLength [3]byte
	Certificates      []Certificate
}

func LoadTrustStore() (roots *x509.CertPool, err error) {
	pem_bytes := []byte(certificate.TRUST_STORE)
	roots = x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(pem_bytes)
	if !ok {
		fmt.Println("failed to parse root certificate", err)
		return nil, fmt.Errorf("failed to parse root certificate")
	}

	return
}

func findLeafCertificate(certificates []Certificate) *x509.Certificate {
	for _, c := range certificates {
		if c.Certificate.IsCA {
			continue
		}
		return c.Certificate
	}
	return nil
}

func findIssuer(certificates []Certificate, issuer string) *x509.Certificate {
	for _, c := range certificates {
		if c.Certificate.IsCA && c.Certificate.Subject.CommonName == issuer {
			return c.Certificate
		}
	}
	return nil
}

func getCertificateChain(certificates []Certificate) []*x509.Certificate {
	// 1. Find leaf certificate
	leaf := findLeafCertificate(certificates)

	// 2. Find issuer certificate
	issuer := findIssuer(certificates, leaf.Issuer.CommonName)

	// 3. Repeat until issuer certificate is not found

	// 4. Return chain
	chain := make([]*x509.Certificate, 2)
	chain[0] = leaf
	chain[1] = issuer
	return chain
}

func (serverCertificate ServerCertificate) Verify(roots *x509.CertPool, host string) (success bool) {

	chain := getCertificateChain(serverCertificate.Certificates)

	chain_pool := x509.NewCertPool()

	for i := 1; i < len(serverCertificate.Certificates); i++ {
		chain_pool.AddCert(serverCertificate.Certificates[i].Certificate)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       host,
		Intermediates: chain_pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	leaf := chain[0]

	chains, err := leaf.Verify(opts)
	if err != nil {
		fmt.Println("[certificate] Verify leaf Verify error", err)
		return
	}

	if chains == nil {
		fmt.Println("[certificate] Verify leaf Verify error chains == nil")
		return false
	}

	return true
}

func ParseServerCertificate(answer []byte) (ServerCertificate, []byte, error) {
	var offset uint32
	offset = 0
	serverCertificate := ServerCertificate{}
	serverCertificate.RecordHeader = ParseRecordHeader(answer[:5])
	offset += 5

	serverCertificate.HandshakeHeader = ParseHandshakeHeader(answer[offset : offset+4])
	offset += 4

	if serverCertificate.HandshakeHeader.MessageType != constants.HandshakeServerCertificate {
		return serverCertificate, answer, helpers.ServerCertificateMissingError()
	}

	copy(serverCertificate.CertificateLength[:], answer[offset:offset+3])
	totalCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(serverCertificate.CertificateLength)
	offset += 3

	// Parsing list of certificates
	var readCertificateLength uint32
	readCertificateLength = 0
	for readCertificateLength < totalCertificateLengthInt {
		currentCertificate := Certificate{}
		copy(currentCertificate.Length[:], answer[offset:offset+3])
		offset += 3

		crtCertificateLengthInt := helpers.Convert3ByteArrayToUInt32(currentCertificate.Length)

		currentCertificate.Content = answer[offset : offset+crtCertificateLengthInt]
		offset += crtCertificateLengthInt

		parsedCertificate, _ := x509.ParseCertificate(currentCertificate.Content)
		currentCertificate.Certificate = parsedCertificate

		serverCertificate.Certificates = append(serverCertificate.Certificates, currentCertificate)
		readCertificateLength += crtCertificateLengthInt + 3 // 3 - size of Length
	}

	//multiple handshake message
	if len(answer[offset:]) > 0 { // 5 is the length of RecordHeader
		serverCertificate.RecordHeader.Length = helpers.ConvertIntToByteArray(uint16(offset) - 5)
	}

	return serverCertificate, answer[offset:], nil
}

// The server sends a sequence (chain) of certificates.
// According to the documentation, the sender's certificate MUST come first in the list.
// Each following certificate MUST directly certify the one preceding it.
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func (serverCertificate ServerCertificate) GetChosenCertificate() *x509.Certificate {
	if len(serverCertificate.Certificates) > 0 {
		return serverCertificate.Certificates[0].Certificate
	}
	return nil
}

func (serverCertificate ServerCertificate) SaveJSON() {
	file, _ := os.OpenFile("ServerCertificate.json", os.O_CREATE, os.ModePerm)
	defer file.Close()
	_ = json.NewEncoder(file).Encode(&serverCertificate)
}

func (serverCertificate ServerCertificate) String() string {
	out := "Server Certificate\n"
	out += fmt.Sprint(serverCertificate.RecordHeader)
	out += fmt.Sprint(serverCertificate.HandshakeHeader)
	out += fmt.Sprintf("  Certificate Lenght.: %x\n", serverCertificate.CertificateLength)
	out += "Certificates:\n"

	for _, c := range serverCertificate.Certificates {
		out += fmt.Sprint(c)
	}
	return out
}

func (serverCertificate *ServerCertificate) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		RecordHeader      RecordHeader    `json:"RecordHeader"`
		HandshakeHeader   HandshakeHeader `json:"HandshakeHeader"`
		CertificateLength uint32          `json:"CertificatesLength"`
		Certificates      []Certificate   `json:"Certificates"`
	}{
		RecordHeader:      serverCertificate.RecordHeader,
		HandshakeHeader:   serverCertificate.HandshakeHeader,
		CertificateLength: helpers.Convert3ByteArrayToUInt32(serverCertificate.CertificateLength),
		Certificates:      serverCertificate.Certificates,
	})
}
