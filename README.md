# Snyk SDK for Go

[![Build](https://img.shields.io/github/workflow/status/guardian/snyk-sdk-go/Build?label=unit+tests)](https://github.com/guardian/snyk-sdk-go/actions/workflows/tests.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/guardian/snyk-sdk-go)](https://goreportcard.com/report/github.com/guardian/snyk-sdk-go)
[![GoDoc](https://img.shields.io/badge/pkg.go.dev-doc-blue)](https://pkg.go.dev/github.com/guardian/snyk-sdk-go)
[![Release](https://img.shields.io/github/v/tag/guardian/snyk-sdk-go?label=release)](https://github.com/guardian/snyk-sdk-go/releases)

_Disclaimer: this SDK is currently in technical preview and not ready for
production usage. This means some aspects of its design and implementation
are not yet considered stable._

snyk-sdk-go is the (un)official Snyk SDK for the Go programming language.

## Installation

```sh
# X.Y.Z is the version you need
go get github.com/guardian/snyk-sdk-go@vX.Y.Z

# for non Go modules usage or latest version
go get github.com/guardian/snyk-sdk-go
```

## Usage

```go
import "github.com/guardian/snyk-sdk-go"
```

Create a new Snyk client, then use the exposed services to access different
parts of the Snyk API.

### Authentication

To use the SDK, you must get your API token from Snyk. You can find your token
in your General Account Settings on https://snyk.io/account/ after you register
with Snyk and log in. See [Authentication for API](https://docs.snyk.io/snyk-api-info/authentication-for-api).

```go
client := snyk.NewClient("your-api-token")
```
