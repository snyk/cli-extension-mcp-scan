package runner //nolint:testpackage // tests need access to internal helpers

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"testing"
)

const testHelloWorld = "hello world"

func writeTempFile(t *testing.T, contents string) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "mcp-scan-checksum-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := f.WriteString(contents); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write temp file: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	return f.Name()
}

func TestVerifyFileChecksum_Matching(t *testing.T) {
	path := writeTempFile(t, testHelloWorld)
	defer os.Remove(path)

	h := sha256.New()
	if _, err := io.WriteString(h, testHelloWorld); err != nil {
		t.Fatalf("failed to hash contents: %v", err)
	}

	expected := fmt.Sprintf("%x", h.Sum(nil))

	ok, err := verifyFileChecksum(path, expected)
	if err != nil {
		t.Fatalf("verifyFileChecksum returned error for matching checksum: %v", err)
	}
	if !ok {
		t.Fatalf("verifyFileChecksum reported mismatch for matching checksum")
	}
}

func TestVerifyFileChecksum_Mismatch(t *testing.T) {
	path := writeTempFile(t, testHelloWorld)
	defer os.Remove(path)

	// Deliberately use an incorrect checksum
	const expected = "0000000000000000000000000000000000000000000000000000000000000000"

	ok, err := verifyFileChecksum(path, expected)
	if err != nil {
		t.Fatalf("verifyFileChecksum returned error for mismatched checksum: %v", err)
	}
	if ok {
		t.Fatalf("verifyFileChecksum reported success for mismatched checksum")
	}
}
