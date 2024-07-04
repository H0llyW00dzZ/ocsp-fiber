// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package ocsp

import (
	"crypto"
	"crypto/x509"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/ocsp"
)

const (
	// MIMEApplicationOCSPRequest is the MIME type for OCSP requests.
	// RFC: https://datatracker.ietf.org/doc/html/rfc6960#page-40
	MIMEApplicationOCSPRequest = "application/ocsp-request"

	// MIMEApplicationOCSPResponse is the MIME type for OCSP responses.
	// RFC: https://datatracker.ietf.org/doc/html/rfc6960#page-40
	MIMEApplicationOCSPResponse = "application/ocsp-response"
)

// Config represents the configuration for the OCSP middleware.
type Config struct {
	// Issuer is the certificate of the issuing CA.
	// It is used to validate the client certificates against the issuer's public key.
	// The Issuer field must be set to a valid [*x509.Certificate].
	Issuer *x509.Certificate

	// Responder is the URL of the OCSP responder.
	// It specifies the endpoint where the OCSP requests will be sent to check the Revocation status of client certificates.
	// The Responder field must be set to a valid URL string.
	Responder string

	// ResponseHandler is a function that handles the response when an error occurs.
	// If not provided, a default JSON response handler will be used.
	ResponseHandler ResponseHandler

	// RequestOptions specifies the options for creating OCSP requests.
	// If not provided, default options will be used.
	RequestOptions RequestOptions
}

// Response represents an OCSP response.
// It embeds the [ocsp.Response] struct and provides additional functionality.
type Response struct {
	*ocsp.Response
}

const (
	// RevocationReasonUnspecified represents an unspecified revocation reason.
	RevocationReasonUnspecified = "Unspecified"

	// RevocationReasonKeyCompromise represents a revocation reason indicating that the key has been compromised.
	RevocationReasonKeyCompromise = "Key Compromise"

	// RevocationReasonCACompromise represents a revocation reason indicating that the CA has been compromised.
	RevocationReasonCACompromise = "CA Compromise"

	// RevocationReasonAffiliationChanged represents a revocation reason indicating that the affiliation has changed.
	RevocationReasonAffiliationChanged = "Affiliation Changed"

	// RevocationReasonSuperseded represents a revocation reason indicating that the certificate has been superseded.
	RevocationReasonSuperseded = "Superseded"

	// RevocationReasonCessationOfOperation represents a revocation reason indicating the cessation of operation.
	RevocationReasonCessationOfOperation = "Cessation Of Operation"

	// RevocationReasonCertificateHold represents a revocation reason indicating that the certificate is on hold.
	RevocationReasonCertificateHold = "Certificate Hold"

	// RevocationReasonRemoveFromCRL represents a revocation reason indicating removal from the CRL.
	RevocationReasonRemoveFromCRL = "Remove From CRL"

	// RevocationReasonPrivilegeWithdrawn represents a revocation reason indicating that the privilege has been withdrawn.
	RevocationReasonPrivilegeWithdrawn = "Privilege Withdrawn"

	// RevocationReasonAACompromise represents a revocation reason indicating that the AA has been compromised.
	RevocationReasonAACompromise = "AA Compromise"

	// RevocationReasonUnknown represents an unknown revocation reason.
	RevocationReasonUnknown = "Unknown"
)

// ResponseHandler is a function that handles the response when an error occurs.
type ResponseHandler func(c *fiber.Ctx, statusCode int, message string) error

// defaultResponseHandler is the default response handler that sends a JSON response.
func defaultResponseHandler(c *fiber.Ctx, statusCode int, message string) error {
	return c.Status(statusCode).JSON(fiber.Map{
		"error": message,
	})
}

// RequestOptions represents the options for creating an OCSP request.
type RequestOptions struct {
	Hash crypto.Hash
}

// createOCSPRequest creates an OCSP request for the given client certificate and issuer.
func createOCSPRequest(clientCert *x509.Certificate, issuer *x509.Certificate, options RequestOptions) ([]byte, error) {
	if options.Hash <= 0 {
		options.Hash = crypto.SHA1 // Default to SHA1 if options.Hash is not set
	}

	return ocsp.CreateRequest(clientCert, issuer, &ocsp.RequestOptions{Hash: options.Hash})
}
