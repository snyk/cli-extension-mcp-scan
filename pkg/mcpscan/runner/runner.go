package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	"time"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	Assets []githubAsset `json:"assets"`
}

func httpGet(ctx workflow.InvocationContext, url string) (*http.Response, error) {
	client := ctx.GetNetworkAccess().GetHttpClient()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}

	return resp, nil
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

func fetchLatestAssetForPlatform(ctx workflow.InvocationContext) (*githubAsset, string, error) {
	prefix, suffix, err := platformAssetMatcher()
	if err != nil {
		return nil, "", err
	}

	resp, err := httpGet(ctx, "https://api.github.com/repos/invariantlabs-ai/mcp-scan/releases/latest")
	if err != nil {
		return nil, "", fmt.Errorf("failed to query GitHub releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to query GitHub releases: unexpected status %s", resp.Status)
	}

	var rel githubRelease
	if decodeErr := json.NewDecoder(resp.Body).Decode(&rel); decodeErr != nil {
		return nil, "", fmt.Errorf("failed to decode GitHub release response: %w", decodeErr)
	}

	var binaryAsset *githubAsset
	var checksumAsset *githubAsset

	for i := range rel.Assets {
		asset := &rel.Assets[i]
		if strings.HasPrefix(asset.Name, prefix) && strings.HasSuffix(asset.Name, suffix) {
			binaryAsset = asset
		}
		if asset.Name == "checksums.txt" {
			checksumAsset = asset
		}
	}

	if binaryAsset == nil {
		return nil, "", fmt.Errorf("no matching asset found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if checksumAsset == nil {
		return nil, "", fmt.Errorf("no checksums.txt asset found in latest release")
	}

	checksumResp, err := httpGet(ctx, checksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download checksums.txt: %w", err)
	}
	defer checksumResp.Body.Close()

	if checksumResp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("failed to download checksums.txt: unexpected status %s", checksumResp.Status)
	}

	checksum, err := parseChecksumForAsset(checksumResp.Body, binaryAsset.Name)
	if err != nil {
		return nil, "", err
	}

	return binaryAsset, checksum, nil
}

func parseChecksumForAsset(r io.Reader, assetName string) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[len(fields)-1]
		if name == assetName {
			return fields[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read checksums.txt: %w", err)
	}
	return "", fmt.Errorf("no checksum entry found for asset %s", assetName)
}

func verifyFileChecksum(path, expected string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("failed to open %s for checksum verification: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("failed to hash %s for checksum verification: %w", path, err)
	}

	actual := fmt.Sprintf("%x", h.Sum(nil))
	return strings.EqualFold(actual, expected), nil
}

// getOrDownloadBinary locates, downloads, verifies and caches the mcp-scan binary for this platform.
//
//nolint:gocyclo // The control flow is a bit involved but kept together for clarity.
func getOrDownloadBinary(ctx workflow.InvocationContext) (string, error) {
	logger := ctx.GetEnhancedLogger()
	asset, checksum, err := fetchLatestAssetForPlatform(ctx)
	if err != nil {
		return "", err
	}

	cacheDir := os.TempDir()
	cachePath := filepath.Join(cacheDir, asset.Name)
	info, err := os.Stat(cachePath)
	progressBar := ctx.GetUserInterface().NewProgressBar()
	//nolint:nestif // The nested structure keeps cache verification and download logic closely related.
	if err == nil && info.Mode().IsRegular() {
		if perr := progressBar.UpdateProgress(0.1); perr != nil {
			logger.Debug().Err(perr).Msg("failed to update progress bar while verifying cached binary")
		}
		progressBar.SetTitle("Verifying cached mcp-scan binary")

		ok, verr := verifyFileChecksum(cachePath, checksum)
		if verr == nil && ok {
			if perr := progressBar.UpdateProgress(1.0); perr != nil {
				logger.Debug().Err(perr).Msg("failed to update progress bar after verifying cached binary")
			}
			progressBar.SetTitle("Using cached mcp-scan binary")

			time.AfterFunc(800*time.Millisecond, func() {
				if cerr := progressBar.Clear(); cerr != nil {
					logger.Debug().Err(cerr).Msg("failed to clear progress bar after using cached binary")
				}
			})
			logger.Debug().Str("path", cachePath).Msg("Using cached mcp-scan binary")
			return cachePath, nil
		}
		logger.Error().Err(verr).Msg("Failed checksum verification of cached mcp-scan binary")
		// If verification fails or errors, fall through to re-download
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to stat cached binary: %w", err)
	}

	if perr := progressBar.UpdateProgress(0.2); perr != nil {
		logger.Debug().Err(perr).Msg("failed to update progress bar before download")
	}
	progressBar.SetTitle("Downloading mcp-scan binary")
	resp, err := httpGet(ctx, asset.BrowserDownloadURL)
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
	progressBar.SetTitle("Verifying downloaded mcp-scan binary")
	if perr := progressBar.UpdateProgress(0.9); perr != nil {
		logger.Debug().Err(perr).Msg("failed to update progress bar before checksum verification")
	}

	ok, verr := verifyFileChecksum(tmpDownload.Name(), checksum)
	if verr != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to verify downloaded binary checksum: %w", verr)
	}
	if !ok {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("checksum verification failed for downloaded binary")
	}

	if err := os.Chmod(tmpDownload.Name(), 0o700); err != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to chmod downloaded binary: %w", err)
	}

	if err := os.Rename(tmpDownload.Name(), cachePath); err != nil {
		_ = os.Remove(tmpDownload.Name())
		return "", fmt.Errorf("failed to move downloaded binary into cache: %w", err)
	}
	if perr := progressBar.UpdateProgress(1.0); perr != nil {
		logger.Debug().Err(perr).Msg("failed to update progress bar after download")
	}
	time.AfterFunc(800*time.Millisecond, func() {
		if cerr := progressBar.Clear(); cerr != nil {
			logger.Debug().Err(cerr).Msg("failed to clear progress bar after download")
		}
	})
	return cachePath, nil
}

// ExecuteBinary writes the binary to a temp file and runs it.
func ExecuteBinary(ctx workflow.InvocationContext, args []string) error {
	logger := ctx.GetEnhancedLogger()
	binaryPath, err := getOrDownloadBinary(ctx)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to prepare mcp-scan binary")
		return err
	}
	logger.Debug().Str("binaryPath", binaryPath).Msg("Executing mcp-scan binary")

	// 1. Create a temporary file
	// The "*" is a placeholder for a random string to ensure uniqueness
	tmpFile, err := os.CreateTemp("", "mcp-scan-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	// 2. Ensure cleanup happens after execution
	// We use a closure to capture the filename
	// defer func() {
	// 	_ = os.Remove(tmpFile.Name())
	// }()

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
	if err := os.Chmod(tmpFile.Name(), 0o700); err != nil {
		return fmt.Errorf("failed to chmod: %w", err)
	}

	// 5. Prepare the command
	//nolint:gosec // tmpFile is a local executable we've just written and chmodded; args are passed as-is from the CLI.
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
