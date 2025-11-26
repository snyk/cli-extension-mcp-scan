package utils_test

import (
	"testing"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/utils"
)

func TestIsValidUUID_Valid(t *testing.T) {
	valid := []string{
		"00000000-0000-0000-0000-000000000000",
		"3b767085-9ff9-4b1a-af9c-6645ade0c205",
	}

	for _, v := range valid {
		if !utils.IsValidUUID(v) {
			t.Errorf("expected %q to be a valid UUID", v)
		}
	}
}

func TestIsValidUUID_Invalid(t *testing.T) {
	invalid := []string{
		"",
		"not-a-uuid",
		"12345",
		"3b767085-9ff9-4b1a-af9c-6645ade0c20Z", // invalid hex char
	}

	for _, v := range invalid {
		if utils.IsValidUUID(v) {
			t.Errorf("expected %q to be an invalid UUID", v)
		}
	}
}
