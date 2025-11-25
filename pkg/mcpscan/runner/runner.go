package runner

import (
	"fmt"
	"os"
	"os/exec"
)

// ExecuteBinary writes the binary to a temp file and runs it
func ExecuteBinary(args []string) error {

	// 1. Create a temporary file
	// The "*" is a placeholder for a random string to ensure uniqueness
	tmpFile, err := os.CreateTemp("", "mcp-scan-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// 2. Ensure cleanup happens after execution
	// We use a closure to capture the filename
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	// 3. Write the embedded bytes to the temp file
	if _, err := tmpFile.Write(binaryData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write binary: %w", err)
	}

	// Close the file descriptor so we can execute it
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	// 4. Make the file executable (0700 = rwx for user)
	if err := os.Chmod(tmpFile.Name(), 0700); err != nil {
		return fmt.Errorf("failed to chmod: %w", err)
	}

	// 5. Prepare the command
	cmd := exec.Command(tmpFile.Name(), args...)

	// Connect standard input/output if you want to see the binary's output
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// 6. Run
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	return nil
}
