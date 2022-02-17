//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func main() {
	if err := genCert(); err != nil {
		panic(err)
	}
	log.Printf("done")
}

func genCert() error {
	log.Printf("generating sm2 ca")

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	ca := &x509.Certificate{
		SerialNumber: serialNumber,

		Subject: pkix.Name{
			Country:      []string{"CN"},
			Organization: []string{"某某科技（深圳）有限公司"},
			Locality:     []string{"深圳市"},
			Province:     []string{"广东省"},

			CommonName: "",
		},

		SignatureAlgorithm: smx509.SM2WithSM3,

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		IsCA:        true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	caPrivKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	caBytes, err := smx509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	saveKeyFile("sm2_ca.key", caPrivKey)
	saveCertFile("sm2_ca.crt", caBytes)

	log.Printf("generating server sm2 double certs")

	{
		sn, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}

		cert := &x509.Certificate{
			SerialNumber: sn,
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"某某科技（深圳）有限公司"},
				Locality:     []string{"深圳市"},
				Province:     []string{"广东省"},
			},

			SignatureAlgorithm: smx509.SM2WithSM3,

			DNSNames:    []string{"localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},

			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0),

			// SubjectKeyId: []byte{1, 2, 3, 4, 6},

			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}

		certPrivKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		certBytes, err := smx509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return err
		}

		saveKeyFile("sm2_server_sign.key", certPrivKey)
		saveCertFile("sm2_server_sign.crt", certBytes)
	}

	{
		sn, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}

		cert := &x509.Certificate{
			SerialNumber: sn,
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"某某科技（深圳）有限公司"},
				Locality:     []string{"深圳市"},
				Province:     []string{"广东省"},
			},

			SignatureAlgorithm: smx509.SM2WithSM3,

			DNSNames:    []string{"localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},

			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0),

			// SubjectKeyId: []byte{1, 2, 3, 4, 6},

			KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}

		certPrivKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		certBytes, err := smx509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return err
		}

		saveKeyFile("sm2_server_enc.key", certPrivKey)
		saveCertFile("sm2_server_enc.crt", certBytes)
	}

	log.Printf("generating client sm2 double certs")

	{
		sn, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return err
		}

		cert := &x509.Certificate{
			SerialNumber: sn,
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"某某科技（深圳）有限公司"},
				Locality:     []string{"深圳市"},
				Province:     []string{"广东省"},
			},

			SignatureAlgorithm: smx509.SM2WithSM3,

			DNSNames:    []string{"localhost"},
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},

			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0),

			// SubjectKeyId: []byte{1, 2, 3, 4, 6},

			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}

		certPrivKey, err := sm2.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		certBytes, err := smx509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
		if err != nil {
			return err
		}

		saveKeyFile("sm2_client_sign.key", certPrivKey)
		saveCertFile("sm2_client_sign.crt", certBytes)
	}

	return nil
}

func saveKeyFile(filename string, priv *sm2.PrivateKey) {
	saveKeyFile_EC(filename, priv)
}

func saveKeyFile_EC(filename string, priv *sm2.PrivateKey) {
	// babassl
	//   openssl ecparam -genkey -name SM2 -outform PEM
	var ecparamSM2 = "BggqgRzPVQGCLQ=="

	privBytes, err := smx509.MarshalSM2PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	privPEM := new(bytes.Buffer)
	pemEncode(privPEM, &pem.Block{Type: "EC PARAMETERS", Bytes: []byte(ecparamSM2)})
	pemEncode(privPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	if err := ioutil.WriteFile(filename, privPEM.Bytes(), 0600); err != nil {
		panic(err)
	}
}

func saveKeyFile_PKCS8(filename string, priv *sm2.PrivateKey) {
	privBytes, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	privPEM := new(bytes.Buffer)
	pemEncode(privPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	if err := ioutil.WriteFile(filename, privPEM.Bytes(), 0600); err != nil {
		panic(err)
	}
}

func saveCertFile(filename string, certBytes []byte) {
	certPEM := new(bytes.Buffer)
	pemEncode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	if err := ioutil.WriteFile(filename, certPEM.Bytes(), 0644); err != nil {
		panic(err)
	}
}

func pemEncode(out io.Writer, b *pem.Block) {
	if err := pem.Encode(out, b); err != nil {
		panic(err)
	}
}
