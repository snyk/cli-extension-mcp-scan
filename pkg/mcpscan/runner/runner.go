package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	Assets []githubAsset `json:"assets"`
}

func platformAssetMatcher() (prefix, suffix string, err error) {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			return "mcp-scan-", "-linux-x86_64", nil
		default:
			return "", "", fmt.Errorf("unsupported linux architecture: %s", runtime.GOARCH)
		}
	case "darwin":
		switch runtime.GOARCH {
		case "arm64":
			return "mcp-scan-", "-macos-arm64", nil
		default:
			return "", "", fmt.Errorf("unsupported darwin architecture: %s", runtime.GOARCH)
		}
	default:
		return "", "", fmt.Errorf("unsupported platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func fetchLatestAssetForPlatform() (*githubAsset, error) {
	prefix, suffix, err := platformAssetMatcher()
	if err != nil {
		return nil, err
	}

	resp, err := http.Get("https://api.github.com/repos/invariantlabs-ai/mcp-scan/releases/latest")
	if err != nil {
		return nil, fmt.Errorf("failed to query GitHub releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to query GitHub releases: unexpected status %s", resp.Status)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to decode GitHub release response: %w", err)
	}

	for _, a := range rel.Assets {
		if strings.HasPrefix(a.Name, prefix) && strings.HasSuffix(a.Name, suffix) {
			return &a, nil
		}
	}

	return nil, fmt.Errorf("no matching asset found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

func getOrDownloadBinary() (string, error) {
	asset, err := fetchLatestAssetForPlatform()
	if err != nil {
		return "", err
	}

	cacheDir := os.TempDir()
	cachePath := filepath.Join(cacheDir, asset.Name)
	info, err := os.Stat(cachePath)
	if err == nil && info.Mode().IsRegular() {
		return cachePath, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to stat cached binary: %w", err)
	}
	fmt.Println("Downloading binary")

	resp, err := http.Get(asset.BrowserDownloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download binary: unexpected status %s", resp.Status)
	}

	tmpDownload, err := os.CreateTemp(cacheDir, asset.Name+".download-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp download file: %w", err)
	}

	_, copyErr := io.Copy(tmpDownload, resp.Body)
	closeErr := tmpDownload.Close()
	if copyErr != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to write downloaded binary: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to close downloaded binary: %w", closeErr)
	}

	if err := os.Chmod(tmpDownload.Name(), 0700); err != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to chmod downloaded binary: %w", err)
	}

	if err := os.Rename(tmpDownload.Name(), cachePath); err != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to move downloaded binary into cache: %w", err)
	}

	return cachePath, nil
}

// ExecuteBinary writes the binary to a temp file and runs it
func ExecuteBinary(args []string) error {
	binaryPath, err := getOrDownloadBinary()
	if err != nil {
		return err
	}

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
	src, err := os.Open(binaryPath)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to open binary for copying: %w", err)
	}
	defer src.Close()

	if _, err := io.Copy(tmpFile, src); err != nil {
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
