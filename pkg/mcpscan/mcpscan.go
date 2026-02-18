package mcpscan

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/errors"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/helpers"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/proxy"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/proxy/interceptor"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/runner"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type ScanResolutionHandlerFunc func(ctx workflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]workflow.Data, error)

const (
	tenantIDFlagPrefix = "--tenant-id="
	clientIDFlagPrefix = "--client-id="
)

func checksumForCurrentPlatform() (string, error) {
	switch runtime.GOOS {
	case "linux":
		if runtime.GOARCH == "amd64" {
			if MCPScanBinaryChecksumLinuxAmd64 == "" {
				return "", fmt.Errorf("checksum not configured for linux/amd64 platform")
			}
			return MCPScanBinaryChecksumLinuxAmd64, nil
		}
	case "darwin":
		if runtime.GOARCH == "arm64" {
			if MCPScanBinaryChecksumMacOSArm64 == "" {
				return "", fmt.Errorf("checksum not configured for darwin/arm64 platform")
			}
			return MCPScanBinaryChecksumMacOSArm64, nil
		}
	}

	return "", fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

//nolint:gocyclo,nestif // Workflow wiring has necessary branching; extracting further would hurt clarity.
func Workflow(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()
	ui := ctx.GetUserInterface()
	engine := ctx.GetEngine()

	experimental := config.GetBool(FlagExperimental)
	json := config.GetBool(FlagJSON)

	isHelp := false
	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}

	checksum, checksumErr := checksumForCurrentPlatform()
	if checksumErr != nil {
		logger.Debug().Err(checksumErr).Msg("Unsupported platform or checksum not configured for mcp-scan binary")
		return nil, checksumErr
	}

	// Process raw args
	rawArgs := config.GetStringSlice(configuration.RAW_CMD_ARGS)

	clientID := config.GetString(FlagClientID)
	if clientID != "" && !utils.IsValidUUID(clientID) {
		err := errors.NewInvalidClientIDError().SnykError
		if outErr := ui.OutputError(err); outErr != nil {
			logger.Error().Err(outErr).Msg("Failed to output invalid client ID error")
		}
		logger.Error().Msg("Client ID is not valid. Must be UUID")
		return nil, err
	}
	tenantID := config.GetString(FlagTenantID)

	if tenantID != "" && !utils.IsValidUUID(tenantID) {
		err := errors.NewInvalidTenantIDError().SnykError
		if outErr := ui.OutputError(err); outErr != nil {
			logger.Error().Err(outErr).Msg("Failed to output invalid tenant ID error")
		}
		logger.Error().Msg("Tenant ID is not valid. Must be UUID")
		return nil, err
	}

	filteredArgs := make([]string, 0, len(rawArgs))
	for _, a := range rawArgs {
		if a == "mcp-scan" || a == "--experimental" {
			continue
		}
		if a == "help" {
			isHelp = true
		}
		if len(a) >= len(tenantIDFlagPrefix) && a[:len(tenantIDFlagPrefix)] == tenantIDFlagPrefix {
			continue
		}
		if len(a) >= len(clientIDFlagPrefix) && a[:len(clientIDFlagPrefix)] == clientIDFlagPrefix {
			continue
		}

		filteredArgs = append(filteredArgs, a)
	}
	// Run help if requested
	if isHelp {
		exitCode, err := runner.ExecuteBinary(ctx, []string{"help"}, MCPScanBinaryVersion, checksum, nil)
		if err != nil {
			logger.Debug().Err(err).Int("exitCode", exitCode).Msg("Error running mcp-scan help binary")
			return nil, fmt.Errorf("failed to run mcp-scan help binary: %w", err)
		}
		return nil, nil
	}

	// 2 modes of operation
	// 1. We're logged in, we retrieve the client id via API and push against the authenticated push endpoint
	// 2. We're not logged in, we expect the client id via parameters and push against the unauthenticated push endpoint
	// 3. Error otherwise

	if clientID == "" {
		isLoggedIn := false

		_, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, config)

		if err == nil {
			isLoggedIn = true
		}

		if isLoggedIn {
			if tenantID == "" {
				if json {
					return nil, fmt.Errorf("tenant ID is required when using --json flag. Please provide it using --tenant-id")
				}
				tenantID, err = helpers.GetTenantID(ctx, tenantID)
				if err != nil {
					return nil, fmt.Errorf("failed to get tenant ID: %w", err)
				}
			}
			clientID, err = helpers.GetClientID(ctx, tenantID)
			if err != nil {
				errorString := strings.ToLower(err.Error())
				var displayErr error
				// Check if this is a forbidden error and use error catalog
				switch {
				case strings.Contains(errorString, "forbidden"):
					displayErr = errors.NewUnauthorizedError("Insufficient permissions to access tenant [evo or tenant-admin].").SnykError
				case strings.Contains(errorString, "unauthorized"):
					displayErr = errors.NewUnauthorizedError("Authentication token is invalid or expired. Run `snyk auth` to re-authenticate.").SnykError
				default:
					displayErr = err
				}

				if outErr := ui.OutputError(displayErr); outErr != nil {
					logger.Error().Err(outErr).Msg("Failed to display error")
				}
				logger.Error().Err(err).Msg("Failed to retrieve client id")
				return nil, fmt.Errorf("failed to retrieve client id: %w", err)
			}
		} else {
			unauthErr := errors.NewUnauthorizedError("Run `snyk auth` or provide valid client id (--client-id=<UUID>)").SnykError
			if outErr := ui.OutputError(unauthErr); outErr != nil {
				logger.Error().Err(outErr).Msg("Failed to output unauthorized error")
			}
			logger.Error().Err(unauthErr).Msg("Snyk auth or provide valid client id (--client-id=<UUID>)")
			return nil, unauthErr
		}
	}
	controlServerURL := fmt.Sprintf("%s/hidden/mcp-scan/push?version=2025-08-28", ctx.GetConfiguration().GetString(configuration.API_URL))
	filteredArgs = append([]string{"scan"}, filteredArgs...)
	filteredArgs = append(filteredArgs,
		"--control-server", controlServerURL,
		"--control-server-H", "x-client-id: "+clientID,
	)
	unameOut, err := exec.Command("uname", "-n").Output()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get uname")
		return nil, fmt.Errorf("failed to get uname: %w", err)
	}
	controlIdentifier := strings.TrimSpace(string(unameOut))
	filteredArgs = append(filteredArgs, "--control-identifier", controlIdentifier)

	// Initialize proxy for credential injection
	caData, err := proxy.InitCA(config, MCPScanBinaryVersion, logger)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to initialize proxy CA")
		return nil, fmt.Errorf("failed to initialize proxy CA: %w", err)
	}

	wrapperProxy, err := proxy.NewWrapperProxy(config, MCPScanBinaryVersion, logger, *caData)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create wrapper proxy")
		return nil, fmt.Errorf("failed to create wrapper proxy: %w", err)
	}

	// Register interceptor to inject credentials via framework's networking layer
	networkInterceptor := interceptor.NewNetworkInjector(ctx)
	wrapperProxy.RegisterInterceptor(networkInterceptor)
	logger.Debug().Msg("Registered network interceptor for credential injection")

	err = wrapperProxy.Start()
	if err != nil {
		logger.Error().Err(err).Msg("Failed to start proxy")
		return nil, fmt.Errorf("failed to start proxy: %w", err)
	}
	defer wrapperProxy.Close()

	proxyInfo := wrapperProxy.ProxyInfo()
	logger.Debug().Int("proxyPort", proxyInfo.Port).Msg("Proxy started successfully")

	// Run the embedded binary
	exitCode, err := runner.ExecuteBinary(ctx, filteredArgs, MCPScanBinaryVersion, checksum, proxyInfo)
	if err != nil {
		logger.Debug().Err(err).Int("exitCode", exitCode).Msg("Error running mcp-scan binary")
		return nil, fmt.Errorf("failed to run mcp-scan binary: %w", err)
	}

	return []workflow.Data{}, nil
}
