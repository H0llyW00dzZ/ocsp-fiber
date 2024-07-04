# ocsp-fiber

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/H0llyW00dzZ/ocsp-fiber.svg)](https://pkg.go.dev/github.com/H0llyW00dzZ/ocsp-fiber)
[![Go Report Card](https://goreportcard.com/badge/github.com/H0llyW00dzZ/ocsp-fiber)](https://goreportcard.com/report/github.com/H0llyW00dzZ/ocsp-fiber)

ocsp-fiber is a Go package that provides an [`OCSP`](https://datatracker.ietf.org/doc/html/rfc6960) (Online Certificate Status Protocol) middleware for the Fiber web framework. It allows to validate the revocation status of client certificates using [`OCSP`](https://datatracker.ietf.org/doc/html/rfc6960) in Fiber applications.

## Features

- Middleware for validating client certificates using OCSP
- Configurable OCSP responder URL and issuer certificate
- Seamless integration with the Fiber web framework
- Easy to use and customize

## Hacking

To ensure the reliability and correctness of the ocsp-fiber package, it includes a set of tests. The tests cover various scenarios and edge cases to validate the behavior of the OCSP middleware.

### Hack Setup

The tests require a valid certificate and key pair for testing purposes. It is important to use a proper certificate and key pair to simulate a production-like environment. Using insecure options like `InsecureSkipVerify` is considered `bad practice` and should be avoided in tests.

To set up the test environment, follow these steps:

1. Obtain a valid certificate and key pair from a trusted (public) or private Certificate Authority (CA) for a domain that you own or control.
2. Place the certificate and key files in the `testdata` directory of the package.
3. Update the test code to load the certificate and key files from the `testdata` directory.

Make sure that the certificate is properly signed by a trusted (public) or private CA and that the domain used in the certificate matches the host you will be testing against.

## License

ocsp-fiber is released under the [BSD 3-Clause License](LICENSE).
