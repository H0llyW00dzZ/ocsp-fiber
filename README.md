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

## License

ocsp-fiber is released under the [BSD 3-Clause License](LICENSE).
