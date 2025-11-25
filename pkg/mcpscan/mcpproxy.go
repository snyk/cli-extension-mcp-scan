package mcpscan

import (
	_ "embed"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/errors"
)



type ProxyResolutionHandlerFunc func(ctx workflow.InvocationContext, config configuration.Configuration, logger *zerolog.Logger) ([]workflow.Data, error)

func McpProxyWorkflow(ctx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()

	experimental := config.GetBool(FlagExperimental)
	
	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		logger.Debug().Msg("Required experimental flag is not present")
		return nil, errors.NewCommandIsExperimentalError().SnykError
	}
	logger.Print("McpScan workflow start")

	if config.GetBool(FlagHelp) {
		fmt.Println("Option")
		// return handleSBOMResolution(ctx, config, logger)
	}
	
	fmt.Println("MCP Proxy")
	// return handleLegacyResolution(ctx, config, logger)
	return []workflow.Data{}, nil
}