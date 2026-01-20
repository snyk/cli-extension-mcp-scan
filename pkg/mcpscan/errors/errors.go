package errors

import (
	cli_errors "github.com/snyk/error-catalog-golang-public/cli"
	snyk_common_errors "github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// McpScanError is a wrapper around snyk_errors to abstract & enable greater control of errors within this repository.
type McpScanError struct {
	SnykError snyk_errors.Error
}

// func NewForbiddenError(msg string) *McpScanError {
// 	return &McpScanError{SnykError: aibom_errors.NewForbiddenError(msg)}
// }

func NewUnauthorizedError(msg string) *McpScanError {
	return &McpScanError{SnykError: snyk_common_errors.NewUnauthorisedError(msg)}
}

// func NewInternalError(msg string) *McpScanError {
// 	return &McpScanError{SnykError: aibom_errors.NewInternalError(msg)}
// }

// func NewNoSupportedFilesError() *McpScanError {
// 	return &McpScanError{SnykError: aibom_errors.NewNoSupportedFilesError("")}
// }

func NewCommandIsExperimentalError() *McpScanError {
	return &McpScanError{SnykError: cli_errors.NewCommandIsExperimentalError("Snyk mcp-scan is experimental and likely to change.")}
}

func NewInvalidTenantIDError() *McpScanError {
	return &McpScanError{SnykError: snyk_common_errors.NewUnauthorisedError("Invalid tenant ID")}
}

func NewInvalidClientIDError() *McpScanError {
	return &McpScanError{SnykError: snyk_common_errors.NewUnauthorisedError("Invalid client ID")}
}
