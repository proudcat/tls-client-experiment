package message

import (
	"crypto/x509"
	"fmt"

	"github.com/proudcat/tls-client-experiment/common"
	"github.com/proudcat/tls-client-experiment/helpers"
	"github.com/proudcat/tls-client-experiment/types"
)

type Certificate struct {
	Length      [3]byte
	Content     []byte
	Certificate *x509.Certificate
}

func (certificate Certificate) String() string {
	out := "........................................................................................................\n"
	out += fmt.Sprintf("    Certificate Length.: %x\n", certificate.Length)
	out += fmt.Sprintf("    Certificate........: %x\n", certificate.Content)
	out += fmt.Sprintf("    Certificate Public Key........: %x\n", certificate.Certificate.PublicKey)
	out += fmt.Sprintf("    Certificate Issuer............: %s\n", certificate.Certificate.Issuer)
	out += fmt.Sprintf("    Signature Algorithm...........: %s\n", certificate.Certificate.SignatureAlgorithm)
	return out
}

type ServerCertificate struct {
	RecordHeader      types.RecordHeader
	HandshakeHeader   types.HandshakeHeader
	CertificateLength [3]byte
	Certificates      []Certificate
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

func (me *ServerCertificate) FromBuffer(buf *common.Buffer) error {

	fmt.Println("Parsing Server Certificate")

	if buf.Size() < types.RECORD_HEADER_SIZE {
		return fmt.Errorf("invalid record size")
	}

	if err := me.RecordHeader.FromBytes(buf.Next(types.RECORD_HEADER_SIZE)); err != nil {
		return err
	}

	if me.RecordHeader.ContentType != types.RECORD_TYPE_HANDSHAKE {
		return fmt.Errorf("invalid record type %v", me.RecordHeader.ContentType)
	}

	buf.AddKey("handshake_start")
	if err := me.HandshakeHeader.FromBytes(buf.Next(types.HANDSHAKE_HEADER_SIZE)); err != nil {
		return err
	}

	if me.HandshakeHeader.Type != types.HS_TYPE_SERVER_CERTIFICATE {
		return fmt.Errorf("invalid handshake type %v", me.HandshakeHeader.Type)
	}

	buf.AddKey("payload_start")

	copy(me.CertificateLength[:], buf.Next(3))

	length := helpers.Bytes2Uint24(me.CertificateLength)

	// Parsing list of certificates
	var offset uint32 = 0
	for offset < length {
		cert := Certificate{}
		copy(cert.Length[:], buf.Next(3))
		cert_length := helpers.Bytes2Uint24(cert.Length)
		cert.Content = buf.Next(int(cert_length))

		x509_cert, _ := x509.ParseCertificate(cert.Content)
		cert.Certificate = x509_cert

		me.Certificates = append(me.Certificates, cert)
		offset += cert_length + 3 // 3 - size of Length
	}

	buf.AddKey("end")

	if int(me.HandshakeHeader.Length) != buf.ClipSize("payload_start", "end") {
		return fmt.Errorf("invalid handshake size")
	}

	//fix content length
	me.RecordHeader.Length = uint16(buf.ClipSize("handshake_start", "end"))

	buf.ClearKeys()

	return nil
}

// The server sends a sequence (chain) of certificates.
// According to the documentation, the sender's certificate MUST come first in the list.
// Each following certificate MUST directly certify the one preceding it.
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func (me ServerCertificate) GetChosenCertificate() *x509.Certificate {
	if len(me.Certificates) > 0 {
		return me.Certificates[0].Certificate
	}
	return nil
}

func (me ServerCertificate) String() string {
	out := "------------------------- Server Certificate ------------------------- \n"
	out += fmt.Sprint(me.RecordHeader)
	out += fmt.Sprint(me.HandshakeHeader)
	out += fmt.Sprintf("Certificate Length.: %x\n", me.CertificateLength)
	out += "Certificates:\n"

	for _, c := range me.Certificates {
		out += fmt.Sprint(c)
	}
	return out
}