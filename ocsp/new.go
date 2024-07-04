// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package ocsp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/ocsp"
)

// New creates a new instance of the OCSP middleware with the provided configuration.
func New(config Config) fiber.Handler {
	// Set default response handler if not provided
	if config.ResponseHandler == nil {
		config.ResponseHandler = defaultResponseHandler
	}

	return func(c *fiber.Ctx) error {
		// Get the TLS connection state from the request context.
		tlsConnState := c.Context().TLSConnectionState()
		if tlsConnState == nil {
			return config.ResponseHandler(c, fiber.StatusBadGateway, "TLS connection state not available")
		}

		// Get the client certificate from the TLS connection state.
		clientCert := tlsConnState.PeerCertificates[0]

		// Create an OCSP request for the client certificate.
		ocspReq, err := createOCSPRequest(clientCert, config.Issuer, config.RequestOptions)
		if err != nil {
			return config.ResponseHandler(c, fiber.StatusInternalServerError, fmt.Sprintf("failed to create OCSP request: %v", err))
		}

		// Create an io.Reader from the OCSP request byte slice.
		ocspReqReader := bytes.NewReader(ocspReq)

		// Send the OCSP request to the responder.
		resp, err := http.Post(config.Responder, MIMEApplicationOCSPRequest, ocspReqReader)
		if err != nil {
			return config.ResponseHandler(c, fiber.StatusInternalServerError, fmt.Sprintf("failed to send OCSP request: %v", err))
		}
		defer resp.Body.Close()

		// Check the response status code.
		if resp.StatusCode != http.StatusOK {
			return config.ResponseHandler(c, resp.StatusCode, fmt.Sprintf("OCSP responder returned status code: %d", resp.StatusCode))
		}

		// Read the OCSP response.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return config.ResponseHandler(c, fiber.StatusInternalServerError, fmt.Sprintf("failed to read OCSP response: %v", err))
		}

		// Parse the OCSP response.
		ocspResp, err := ocsp.ParseResponse(body, config.Issuer)
		if err != nil {
			return config.ResponseHandler(c, fiber.StatusInternalServerError, fmt.Sprintf("failed to parse OCSP response: %v", err))
		}

		// Create a new Response instance
		ocspRes := Response{Response: ocspResp}

		// Check the OCSP response status.
		if ocspResp.Status == ocsp.Revoked {
			reasonMessage := ocspRes.getRevocationReasonMessage(ocspResp.RevocationReason)
			return config.ResponseHandler(c, fiber.StatusUnauthorized, fmt.Sprintf("Certificate revoked: %s", reasonMessage))
		} else if ocspResp.Status != ocsp.Good {
			return config.ResponseHandler(c, fiber.StatusUnauthorized, "Certificate status is unknown")
		}

		return c.Next()
	}
}

// getRevocationReasonMessage returns a human-readable message for the given Revocation reason.
func (resp *Response) getRevocationReasonMessage(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return RevocationReasonUnspecified
	case ocsp.KeyCompromise:
		return RevocationReasonKeyCompromise
	case ocsp.CACompromise:
		return RevocationReasonCACompromise
	case ocsp.AffiliationChanged:
		return RevocationReasonAffiliationChanged
	case ocsp.Superseded:
		return RevocationReasonSuperseded
	case ocsp.CessationOfOperation:
		return RevocationReasonCessationOfOperation
	case ocsp.CertificateHold:
		return RevocationReasonCertificateHold
	case ocsp.RemoveFromCRL:
		return RevocationReasonRemoveFromCRL
	case ocsp.PrivilegeWithdrawn:
		return RevocationReasonPrivilegeWithdrawn
	case ocsp.AACompromise:
		return RevocationReasonAACompromise
	default:
		return RevocationReasonUnknown
	}
}
