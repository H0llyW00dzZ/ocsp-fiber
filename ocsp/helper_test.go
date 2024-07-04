// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package ocsp_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/gofiber/fiber/v2"
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
