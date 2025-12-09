package mcpscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "mcp-scan"

	MCPScanBinaryVersion = "0.3.34"

	MCPScanBinaryChecksumLinuxAmd64 = "bb11227d428d9d2254eab6eb09e6d3c0921e432857e405043270d7b90278d417"
	MCPScanBinaryChecksumMacOSArm64 = "2b78381d287372179362c7107d58a8ac473733e8f8ab41d25c639fc32e6e9af4"
)

var (
	ScanWorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier(ScanWorkflowIDStr)

	ScanDataTypeID workflow.Identifier = workflow.NewTypeIdentifier(ScanWorkflowID, ScanWorkflowIDStr)
)

// Init initializes the DepGraph workflow.
func Init(engine workflow.Engine) error {
	flags := getFlagSet()
	engine.GetConfiguration().AddAlternativeKeys(FlagTenantID, []string{"SNYK_TENANT_ID"})
	_, err := engine.Register(
		ScanWorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		Workflow)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}

	return nil
}
