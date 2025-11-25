package mcpscan

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ScanWorkflowIDStr = "mcp-scan"
	ProxyWorkflowIDStr = "mcp-proxy"
)

var (
	// WorkflowID is the unique identifier for this workflow. It should be used as
	// a reference everywhere.
	ScanWorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier(ScanWorkflowIDStr)
	ProxyWorkflowID workflow.Identifier = workflow.NewWorkflowIdentifier(ProxyWorkflowIDStr)

	// DataTypeID is the unique identifier for the data type that is being returned
	// from this workflow.
	ScanDataTypeID workflow.Identifier = workflow.NewTypeIdentifier(ScanWorkflowID, ScanWorkflowIDStr)
	ProxyDataTypeID workflow.Identifier = workflow.NewTypeIdentifier(ProxyWorkflowID, ProxyWorkflowIDStr)
)

// Init initializes the DepGraph workflow.
func Init(engine workflow.Engine) error {
	flags := getFlagSet()

	_, err := engine.Register(
		ScanWorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		McpScanWorkflow)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}
	_, err = engine.Register(
		ProxyWorkflowID,
		workflow.ConfigurationOptionsFromFlagset(flags),
		McpProxyWorkflow)
	if err != nil {
		return fmt.Errorf("failed to register workflow: %w", err)
	}

	return nil
}