package helpers_test

import (
	"testing"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/helpers"
)

// Test that GetTenantID respects an already provided tenantID without needing ctx.
func TestGetTenantID_ReturnsProvidedID(t *testing.T) {
	const expected = "tenant-1234"

	// ctx is nil here on purpose; implementation should short-circuit on non-empty tenantID
	got, err := helpers.GetTenantID(nil, expected)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}
