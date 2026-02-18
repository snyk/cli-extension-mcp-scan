package runner

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
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

func fetchAssetForVersionAndPlatform(_ workflow.InvocationContext, version string) (*githubAsset, error) {
	prefix, suffix, err := platformAssetMatcher()
	if err != nil {
		return nil, err
	}
	trimmedVersion := strings.TrimSpace(version)
	if trimmedVersion == "" {
		return nil, fmt.Errorf("version must not be empty")
	}

	assetName := prefix + trimmedVersion + suffix
	tag := "v" + trimmedVersion
	downloadURL := "https://github.com/invariantlabs-ai/mcp-scan/releases/download/" + url.PathEscape(tag) + "/" + url.PathEscape(assetName)

	return &githubAsset{
		Name:               assetName,
		BrowserDownloadURL: downloadURL,
	}, nil
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
func getOrDownloadBinary(ctx workflow.InvocationContext, version, checksum string) (string, error) {
	logger := ctx.GetEnhancedLogger()
	asset, err := fetchAssetForVersionAndPlatform(ctx, version)
	if err != nil {
		return "", err
	}

	config := ctx.GetConfiguration()
	cacheDir := config.GetString(configuration.CACHE_PATH)
	if cacheDir == "" {
		cacheDir = os.TempDir()
	}
	if mkdirErr := os.MkdirAll(cacheDir, 0o755); mkdirErr != nil {
		return "", fmt.Errorf("failed to create cache directory %s: %w", cacheDir, mkdirErr)
	}
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
		if verr != nil {
			logger.Error().Err(verr).Msg("Failed to verify checksum of cached mcp-scan binary")
			if cerr := progressBar.Clear(); cerr != nil {
				logger.Debug().Err(cerr).Msg("failed to clear progress bar after cached checksum verification error")
			}
			return "", fmt.Errorf("failed to verify checksum of cached mcp-scan binary: %w", verr)
		}
		if !ok {
			logger.Error().Msg("Checksum verification failed for cached mcp-scan binary")
			if cerr := progressBar.Clear(); cerr != nil {
				logger.Debug().Err(cerr).Msg("failed to clear progress bar after cached checksum mismatch")
			}
			return "", fmt.Errorf("checksum verification failed for cached mcp-scan binary")
		}

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
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to stat cached binary: %w", err)
	}

	if perr := progressBar.UpdateProgress(0.2); perr != nil {
		logger.Debug().Err(perr).Msg("failed to update progress bar before download")
	}
	progressBar.SetTitle("Downloading mcp-scan binary")
	json := config.GetBool("json")
	if !json {
		if outErr := ctx.GetUserInterface().Output(fmt.Sprintf("Disclaimer: Downloading mcp-scan binary from %s", asset.BrowserDownloadURL)); outErr != nil {
			logger.Debug().Err(outErr).Msg("failed to output download disclaimer")
		}
	}
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
		if cerr := progressBar.Clear(); cerr != nil {
			logger.Debug().Err(cerr).Msg("failed to clear progress bar after downloaded checksum verification error")
		}
		return "", fmt.Errorf("failed to verify downloaded binary checksum: %w", verr)
	}
	if !ok {
		_ = os.Remove(tmpDownload.Name())
		if cerr := progressBar.Clear(); cerr != nil {
			logger.Debug().Err(cerr).Msg("failed to clear progress bar after downloaded checksum mismatch")
		}
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
// Returns the exit code and error. If the binary exits with a non-zero code,
// the error will be non-nil and contain the exit code information.
func ExecuteBinary(ctx workflow.InvocationContext, args []string, version, checksum string, proxyInfo interface{}) (int, error) {
	logger := ctx.GetEnhancedLogger()
	binaryPath, err := getOrDownloadBinary(ctx, version, checksum)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to prepare mcp-scan binary")
		return -1, err
	}
	logger.Debug().Str("binaryPath", binaryPath).Msg("Executing mcp-scan binary")

	// 1. Create a temporary file
	// The "*" is a placeholder for a random string to ensure uniqueness
	tmpFile, err := os.CreateTemp("", "mcp-scan-*")
	if err != nil {
		return -1, fmt.Errorf("failed to create temp file: %w", err)
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
		return -1, fmt.Errorf("failed to open binary for copying: %w", err)
	}
	defer src.Close()

	if _, copyErr := io.Copy(tmpFile, src); copyErr != nil {
		_ = tmpFile.Close()
		return -1, fmt.Errorf("failed to write binary: %w", copyErr)
	}

	// Close the file descriptor so we can execute it
	if closeErr := tmpFile.Close(); closeErr != nil {
		return -1, fmt.Errorf("failed to close file: %w", closeErr)
	}

	// 4. Make the file executable (0700 = rwx for user)
	if chmodErr := os.Chmod(tmpFile.Name(), 0o700); chmodErr != nil {
		return -1, fmt.Errorf("failed to chmod: %w", chmodErr)
	}

	// 5. Prepare the command
	//nolint:gosec // tmpFile is a local executable we've just written and chmodded; args are passed as-is from the CLI.
	cmd := exec.Command(tmpFile.Name(), args...)

	// Configure proxy if provided
	if proxyInfo != nil {
		// Type assert to get the proxy info structure
		type ProxyInfo struct {
			Port                int
			Password            string
			CertificateLocation string
		}
		if pi, ok := proxyInfo.(*ProxyInfo); ok {
			// Set proxy environment variables
			proxyURL := fmt.Sprintf("http://snykcli:%s@127.0.0.1:%d", pi.Password, pi.Port)
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
				fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
				fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", pi.CertificateLocation),
			)
			logger.Debug().
				Str("proxyURL", fmt.Sprintf("http://snykcli:***@127.0.0.1:%d", pi.Port)).
				Str("certLocation", pi.CertificateLocation).
				Msg("Configured binary to use proxy")
		}
	}

	// Connect standard input/output if you want to see the binary's output
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// 6. Run and capture exit code
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			logger.Debug().Int("exitCode", exitCode).Msg("Binary exited with non-zero code")
			return exitCode, fmt.Errorf("execution failed with exit code %d: %w", exitCode, err)
		}
		return -1, fmt.Errorf("execution failed: %w", err)
	}

	return exitCode, nil
}
