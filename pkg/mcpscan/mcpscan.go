package mcpscan

import (
	"os"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/errors"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/helpers"
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

//nolint:gocyclo,nestif // Workflow wiring has necessary branching; extracting further would hurt clarity.
func Workflow(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()
	ui := ctx.GetUserInterface()
	engine := ctx.GetEngine()

	experimental := config.GetBool(FlagExperimental)
	isHelp := false
	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}

	// Process raw args
	rawArgs := config.GetStringSlice(configuration.RAW_CMD_ARGS)

	clientID := config.GetString("client-id")
	if clientID != "" && !utils.IsValidUUID(clientID) {
		logger.Fatal().Msg("Client ID is not valid. Must be UUID")
	}
	tenantID := config.GetString("tenant-id")
	if tenantID == "" {
		tenantID = os.Getenv("SNYK_TENANT_ID")
	}
	if tenantID != "" && !utils.IsValidUUID(tenantID) {
		logger.Fatal().Msg("Tenant ID is not valid. Must be UUID")
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
		if err := runner.ExecuteBinary(ctx, []string{"help"}); err != nil {
			logger.Fatal().Err(err).Msg("Error running binary")
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
				tenantID = helpers.GetTenantID(ctx, tenantID)
			}
			clientID, err = helpers.GetClientID(ctx, tenantID)
			if err != nil {
				if outErr := ui.OutputError(err); outErr != nil {
					logger.Error().Err(outErr).Msg("Failed to output client id retrieval error")
				}
				logger.Fatal().Err(err).Msg("Failed to retrieve client id")
			}
		} else {
			unauthErr := errors.NewUnauthorizedError("Run `snyk auth` or provide valid client id (--client-id=<UUID>)").SnykError
			if outErr := ui.OutputError(unauthErr); outErr != nil {
				logger.Error().Err(outErr).Msg("Failed to output unauthorized error")
			}
			logger.Fatal().Err(unauthErr).Msg("Snyk auth or provide valid client id (--client-id=<UUID>)")
		}
	}

	filteredArgs = append([]string{"scan"}, filteredArgs...)
	filteredArgs = append(filteredArgs,
		"--control-server", "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28",
		"--control-server-H", "x-client-id: "+clientID,
	)
	unameOut, err := exec.Command("uname", "-n").Output()
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to get uname")
	}
	controlIdentifier := strings.TrimSpace(string(unameOut))
	filteredArgs = append(filteredArgs, "--control-identifier", controlIdentifier)
	// Run the embedded binary
	if err := runner.ExecuteBinary(ctx, filteredArgs); err != nil {
		logger.Fatal().Err(err).Msg("Error running binary")
	}

	return []workflow.Data{}, nil
}
