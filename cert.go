package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	// "encoding/pem"
	"math/big"
	"net"
	"time"
)

// REF: https://www.socketloop.com/tutorials/golang-create-x509-certificate-private-and-public-keys
func CreateX509Cert(
	parentCert *x509.Certificate, parentKey *rsa.PrivateKey,
	commonName string, dnsNames []string, ipAddresses []net.IP,
) (certBytes []byte, privateKey *rsa.PrivateKey, err error) {
	// ok, lets populate the certificate with some data
	// not all fields in Certificate will be populated
	// see Certificate structure at
	// http://golang.org/pkg/crypto/x509/#Certificate
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"AppNode User"},
		},

		NotBefore: time.Now().AddDate(0, 0, -1), // 往前一天，防止PC时间不准确
		NotAfter:  time.Now().AddDate(10, 0, 0), // 10年
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		BasicConstraintsValid: true,
		IsCA: false,

		SubjectKeyId: []byte{0x61, 0x70, 0x70, 0x6e, 0x6f, 0x64, 0x65}, // appnode

		// OCSPServer:            []string{"www.appnode.com"},
		IssuingCertificateURL: []string{"https://www.appnode.com/"},

		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		// Subject Alternate Name values
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}
	if commonName != "" {
		template.Subject.CommonName = commonName
	}

	// generate private key
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	publicKey := &privateKey.PublicKey

	// create a certificate.
	certBytes, err = x509.CreateCertificate(rand.Reader, template, parentCert, publicKey, parentKey)
	if err != nil {
		return
	}

	// // save private key
	// privKey = x509.MarshalPKCS1PrivateKey(privateKey)

	// // save public key
	// pubKey, _ := x509.MarshalPKIXPublicKey(publicKey)

	// // this will create plain text PEM file.
	// pemkey := &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	// certPem = pem.EncodeToMemory(pemkey)
	return
}
