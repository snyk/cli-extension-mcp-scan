package mcpscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "mcp-scan"

	MCPScanBinaryVersion = "0.4.2"

	MCPScanBinaryChecksumLinuxAmd64 = "06d372791ae93b5384da5c81b87e9c816ac7756c1d56810dd05329bfc10b5613"
	MCPScanBinaryChecksumMacOSArm64 = "acb0ddc751d8dd8aba7243e366758e1d6d0b12b674f5ea900357dc79ac6de0fe"
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
