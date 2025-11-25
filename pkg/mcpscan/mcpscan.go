package mcpscan

import (
	_ "embed"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/errors"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/runner"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type ScanResolutionHandlerFunc func(ctx workflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]workflow.Data, error)

func McpScanWorkflow(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	experimental := config.GetBool(FlagExperimental)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}

	// func InitTestDelta(engine workflow.Engine) error {
	// flagset := pflag.NewFlagSet("test-delta", pflag.ContinueOnError)
	// flagset.StringSlice(configuration.RAW_CMD_ARGS, os.Args[1:], "Command line arguments for the legacy CLI.")
	// flagset.Bool(configuration.WORKFLOW_USE_STDIO, false, "Use StdIn and StdOut")
	// flagset.String(configuration.WORKING_DIRECTORY, "", "CLI working directory")

	rawArgs := config.GetStringSlice(configuration.RAW_CMD_ARGS)

	filteredArgs := make([]string, 0, len(rawArgs))
	for _, a := range rawArgs {
		if a == "mcp-scan" || a == "--experimental" {
			continue
		}
		filteredArgs = append(filteredArgs, a)
	}

	logger.Print("McpScan workflow start")

	// Run the embedded binary
	if err := runner.ExecuteBinary(filteredArgs); err != nil {
		logger.Fatal().Err(err).Msg("Error running binary")
	}

	fmt.Println("MCP Scan")

	// return handleLegacyResolution(ctx, config, logger)
	return []workflow.Data{}, nil
}
