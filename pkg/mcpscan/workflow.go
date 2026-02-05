package mcpscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "mcp-scan"

	MCPScanBinaryVersion = "0.4"

	MCPScanBinaryChecksumLinuxAmd64 = "3917146753bf36105bdfbbf29c9d972f1daa2d7621ba984875384e4f1c2ad88a"
	MCPScanBinaryChecksumMacOSArm64 = "f8d265fbcea8f58788bb0ee558788fe03c4d2a1ecb8efef3169bcce3ea13812c"
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
