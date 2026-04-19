package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// LoadOrGenerate loads TLS config from cert/key files, or generates a self-signed cert
func LoadOrGenerate(certFile, keyFile string) (*tls.Config, error) {
	// Try loading from files first
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, fmt.Errorf("loading TLS cert/key: %w", err)
			}
			return buildTLSConfig(cert), nil
		}
	}

	// Generate self-signed cert
	fmt.Println("[tls] Generating self-signed certificate...")
	cert, err := generateSelfSigned(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("generating self-signed cert: %w", err)
	}
	fmt.Printf("[tls] Self-signed cert saved to %s / %s\n", certFile, keyFile)
	return buildTLSConfig(cert), nil
}

func buildTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

func generateSelfSigned(certOut, keyOut string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Go Session Server"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("0.0.0.0")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Write cert file
	if certOut != "" {
		if err := os.MkdirAll(dirOf(certOut), 0o700); err == nil {
			cf, _ := os.Create(certOut)
			pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
			cf.Close()
		}
	}

	// Write key file
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	if keyOut != "" {
		if err := os.MkdirAll(dirOf(keyOut), 0o700); err == nil {
			kf, _ := os.OpenFile(keyOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
			kf.Close()
		}
	}

	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return "."
}
