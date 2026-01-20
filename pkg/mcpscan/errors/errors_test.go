package errors_test

import (
	"testing"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/errors"
)

const (
	errNonNil      = "expected error to be non-nil"
	errNonEmptyMsg = "expected error message to be non-empty"
)

func TestNewUnauthorizedError(t *testing.T) {
	msg := "test unauthorized message"
	err := errors.NewUnauthorizedError(msg)

	if err == nil {
		t.Fatal(errNonNil)
	}

	if err.SnykError.Error() == "" {
		t.Error(errNonEmptyMsg)
	}
}

func TestNewCommandIsExperimentalError(t *testing.T) {
	err := errors.NewCommandIsExperimentalError()

	if err == nil {
		t.Fatal(errNonNil)
	}

	if err.SnykError.Error() == "" {
		t.Error(errNonEmptyMsg)
	}
}

func TestNewInvalidTenantIDError(t *testing.T) {
	err := errors.NewInvalidTenantIDError()

	if err == nil {
		t.Fatal(errNonNil)
	}

	if err.SnykError.Error() == "" {
		t.Error(errNonEmptyMsg)
	}
}

func TestNewInvalidClientIDError(t *testing.T) {
	err := errors.NewInvalidClientIDError()

	if err == nil {
		t.Fatal(errNonNil)
	}

	if err.SnykError.Error() == "" {
		t.Error(errNonEmptyMsg)
	}
}

func TestMcpScanErrorType(t *testing.T) {
	err := errors.NewUnauthorizedError("test")

	if _, ok := interface{}(err).(*errors.McpScanError); !ok {
		t.Error("expected error to be of type *McpScanError")
	}
}
