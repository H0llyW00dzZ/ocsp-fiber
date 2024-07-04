// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package ocsp_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/ocsp"
)

func createCertPoolFromFile(certFilePath string) (*x509.CertPool, error) {
	// Read the CA certificate from the file
	caCert, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}

	// Create a new certificate pool
	certPool := x509.NewCertPool()

	// Append the CA certificate to the pool
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("error appending CA certificate to pool")
	}

	return certPool, nil
}

func tlsServerConfig(cert tls.Certificate) *tls.Config {
	tlsHandler := &fiber.TLSHandler{}
	RootCA, _ := createCertPoolFromFile("boring-ca.pem")
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		Certificates:   []tls.Certificate{cert},
		RootCAs:        RootCA,
		GetCertificate: tlsHandler.GetClientInfo,
		ClientAuth:     tls.RequireAndVerifyClientCert,
	}
}

func loadCertificate(path string) *x509.Certificate {
	// Read the certificate file.
	certPEM, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Parse the certificate PEM block.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	// Parse the certificate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return cert
}

func generateTestCertificate() (*x509.Certificate, crypto.PrivateKey, error) {
	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create a self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func generateOCSPResponse(cert, issuer *x509.Certificate, privateKey crypto.PrivateKey) ([]byte, error) {
	// Type-assert the private key to *ecdsa.PrivateKey
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to type-assert private key to *ecdsa.PrivateKey")
	}

	// Create an OCSP response template
	template := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	// Create the OCSP response
	ocspResp, err := ocsp.CreateResponse(issuer, issuer, template, ecdsaPrivateKey)
	if err != nil {
		return nil, err
	}

	return ocspResp, nil
}

func generateRevokedOCSPResponse(cert, issuer *x509.Certificate, privateKey crypto.PrivateKey, reason int) ([]byte, error) {
	// Type-assert the private key to *ecdsa.PrivateKey
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to type-assert private key to *ecdsa.PrivateKey")
	}

	// Create an OCSP response template
	template := ocsp.Response{
		Status:           ocsp.Revoked,
		SerialNumber:     cert.SerialNumber,
		ThisUpdate:       time.Now(),
		NextUpdate:       time.Now().Add(24 * time.Hour),
		RevocationReason: reason,
		RevokedAt:        time.Now(),
	}

	// Create the OCSP response
	ocspResp, err := ocsp.CreateResponse(issuer, issuer, template, ecdsaPrivateKey)
	if err != nil {
		return nil, err
	}

	return ocspResp, nil
}
