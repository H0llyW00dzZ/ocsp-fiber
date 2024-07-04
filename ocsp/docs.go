// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

// Package ocsp provides middleware for validating client certificates using OCSP (Online Certificate Status Protocol) RFC 6960.
//
// The OCSP middleware checks the revocation status of client certificates by sending OCSP requests to a specified OCSP responder.
// It ensures that only valid and non-revoked certificates are allowed to access protected routes.
//
// # Usage
//
//	import (
//		"github.com/gofiber/fiber/v2"
//		"github.com/H0llyW00dzZ/ocsp-fiber/ocsp"
//	)
//
//	func main() {
//		app := fiber.New()
//
//		ocspMiddleware := ocsp.New(ocsp.Config{
//			Issuer:    issuerCert,
//			Responder: "http://ocsp.example.com",
//		})
//
//		app.Use(ocspMiddleware)
//
//		// Define your routes and start the server
//		// ...
//	}
//
// # Configuration
//
// The OCSP middleware is configured using the [ocsp.Config] struct. The important fields are:
//
//   - Issuer: The certificate of the issuing CA. It is used to validate the client certificates against the issuer's public key.
//   - Responder: The URL of the OCSP responder. It specifies the endpoint where the OCSP requests will be sent to check the revocation status of client certificates.
//   - ResponseHandler: A function that handles the response when an error occurs. If not provided, a default JSON response handler will be used.
//
// # Revocation Reasons
//
// The OCSP middleware defines constants for various revocation reasons. These constants provide human-readable descriptions for the revocation reasons returned by the OCSP responder.
//
//   - [RevocationReasonUnspecified]: Unspecified revocation reason.
//   - [RevocationReasonKeyCompromise]: The key has been compromised.
//   - [RevocationReasonCACompromise]: The CA has been compromised.
//   - [RevocationReasonAffiliationChanged]: The affiliation has changed.
//   - [RevocationReasonSuperseded]: The certificate has been superseded.
//   - [RevocationReasonCessationOfOperation]: Cessation of operation.
//   - [RevocationReasonCertificateHold]: The certificate is on hold.
//   - [RevocationReasonRemoveFromCRL]: Removed from the CRL.
//   - [RevocationReasonPrivilegeWithdrawn]: The privilege has been withdrawn.
//   - [RevocationReasonAACompromise]: The AA has been compromised.
//   - [RevocationReasonUnknown]: Unknown revocation reason.
//
// # OCSP Response
//
// The [ocsp.Response] struct represents an OCSP response. It embeds the [ocsp.Response] struct from the [golang.org/x/crypto/ocsp] package
// and provides additional functionality. The Response struct allows access to the fields and methods of the embedded [ocsp.Response] struct,
// such as Status, SerialNumber, RevocationReason, RevokedAt, ThisUpdate, NextUpdate, and Extensions.
//
// The Response struct is used to create a new instance of the OCSP response after parsing the response received from the OCSP responder.
// It provides a structured and convenient way to work with the OCSP response data.
package ocsp
