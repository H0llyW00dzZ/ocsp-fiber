// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package ocsp_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/H0llyW00dzZ/ocsp-fiber/ocsp"
	"github.com/gofiber/fiber/v2"
)

func TestOCSPMiddleware_NonTLSConnection(t *testing.T) {
	// Create the OCSP middleware with a dummy configuration.
	ocspMiddleware := ocsp.New(ocsp.Config{})

	// Create a new Fiber app.
	app := fiber.New()

	// Use the OCSP middleware.
	app.Use(ocspMiddleware)

	// Define a test route.
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	// Create a new HTTP request without TLS.
	req := httptest.NewRequest("GET", "/", nil)

	// Perform the request.
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to perform request: %v", err)
	}

	// Check the response status code.
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Unexpected status code. Expected: %d, Got: %d", http.StatusBadGateway, resp.StatusCode)
	}
}

func loadPrivateKey(path string) crypto.PrivateKey {
	// Read the private key file.
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Parse the private key PEM block.
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		panic("failed to parse private key PEM")
	}

	// Parse the private key.
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key
}

func TestOCSPMiddleware_ErrorCases(t *testing.T) {
	// Load the issuer certificate.
	issuerCert := loadCertificate("testdata/issuer.crt")

	// Create a mock OCSP responder.
	responder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a successful OCSP response.
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mock-ocsp-response"))
	}))
	defer responder.Close()

	// Create the OCSP middleware with the configuration.
	ocspMiddleware := ocsp.New(ocsp.Config{
		Issuer: issuerCert,
		ResponderFunc: func(cert *x509.Certificate) string {
			return responder.URL
		},
	})

	// Create a new Fiber app
	app := fiber.New(fiber.Config{
		Prefork: false, // Disable prefork to avoid issues with TLS1.3 and concurrent connections
	})

	// Use the OCSP middleware.
	app.Use(ocspMiddleware)

	// Define a test route
	app.Get("/test", func(c *fiber.Ctx) error {
		if c.Secure() {
			return c.JSON(fiber.Map{
				"message": "Hello, World! (via TLS)",
			})
		}
		return c.SendString("Hello, World!")
	})

	// Load the self-signed certificate and key
	cert, err := tls.LoadX509KeyPair("testdata/boring-cert.pem", "testdata/boring-key.pem")
	if err != nil {
		t.Fatal(err)
	}

	// Create a TLS configuration for the server
	tlsServerConfig := tlsServerConfig(cert)

	// Create a regular TCP listener
	ln, err := net.Listen(app.Config().Network, ":443")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(ln, tlsServerConfig)
	defer ln.Close()

	tlsHandler := &fiber.TLSHandler{}
	// Start the server with the Custom Listener
	go func() {
		app.SetTLSHandler(tlsHandler)
		if err := app.Listener(tlsListener); err != nil {
			t.Error(err)
		}
	}()

	// Define different curve preferences for each transport
	curvePreferences := [][]tls.CurveID{
		{tls.CurveP384, tls.CurveP521, tls.X25519, tls.CurveP256},
		{tls.CurveP521, tls.X25519, tls.CurveP256, tls.CurveP384},
		{tls.X25519, tls.CurveP384, tls.CurveP521, tls.CurveP256},
	}

	certPool, err := createCertPoolFromFile("testdata/boring-ca.pem")
	if err != nil {
		t.Fatalf("Failed to create certificate pool: %v", err)
	}

	transports := make([]*http.Transport, len(curvePreferences))
	for i, curves := range curvePreferences {
		transports[i] = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:       tls.VersionTLS13,
				ServerName:       "localhost",
				CurvePreferences: curves,
				ClientCAs:        certPool,
				Certificates:     tlsServerConfig.Clone().Certificates,
			},
		}
	}

	// Create multiple clients with different transports
	clients := make([]*http.Client, len(transports))
	for i, transport := range transports {
		clients[i] = &http.Client{
			Transport: transport,
		}
	}

	// Make requests to the server using each client
	for _, client := range clients {
		req, err := http.NewRequest("GET", "https://localhost:443/test", nil)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		expectedBody := `{"error":"failed to parse OCSP response: asn1: structure error: tags don't match (16 vs {class:1 tag:13 length:111 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:\u003cnil\u003e tag:\u003cnil\u003e stringType:0 timeType:0 set:false omitEmpty:false} responseASN1 @2"}`
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status code %d, but got %d", http.StatusInternalServerError, resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if string(body) != expectedBody {
			t.Errorf("Expected response body to be '%s', but got '%s'", expectedBody, string(body))
		}
	}
}
