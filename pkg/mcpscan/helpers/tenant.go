package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/helpers/tenantsapi"
	"github.com/snyk/cli-extension-mcp-scan/pkg/mcpscan/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func GetTenantID(ctx workflow.InvocationContext, tenantID string) (string, error) {
	if tenantID != "" {
		return tenantID, nil
	}

	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()
	ui := ctx.GetUserInterface()
	context := ctx.Context()

	httpClient := ctx.GetNetworkAccess().GetHttpClient()
	tenantsClient, err := tenantsapi.NewClientWithResponses(config.GetString(configuration.API_URL), httpClient)
	if err != nil {
		if outErr := ui.OutputError(err); outErr != nil {
			logger.Error().Err(outErr).Msg("Failed to output tenant client creation error")
		}
		logger.Error().Err(err).Msg("Failed to create tenants client")
		return "", fmt.Errorf("failed to create tenants client: %w", err)
	}

	limit := int32(100)
	listTenantsParams := &tenantsapi.ListTenantsParams{
		Limit: &limit,
	}
	tenantsResp, err := tenantsapi.ListTenants(context, tenantsClient, listTenantsParams)
	if err != nil {
		if outErr := ui.OutputError(err); outErr != nil {
			logger.Error().Err(outErr).Msg("Failed to output tenant check error")
		}
		logger.Error().Err(err).Msg("Error checking tenants")
		return "", fmt.Errorf("error checking tenants: %w", err)
	}

	availableTenants := tenantsResp.Tenants
	if len(availableTenants) == 0 {
		logger.Error().Msg("No available tenants found")
		return "", fmt.Errorf("no available tenants found")
	}

	if len(availableTenants) == 1 {
		tenantID = availableTenants[0].ID
		return tenantID, nil
	}

	tenantName := []string{}
	for _, tenant := range availableTenants {
		tenantName = append(tenantName, tenant.Name)
	}
	_, selectedTenantName, selErr := ui.SelectOptions("Select tenant", tenantName)
	if selErr != nil {
		if outErr := ui.OutputError(selErr); outErr != nil {
			logger.Error().Err(outErr).Msg("Failed to output tenant selection error")
		}
		logger.Error().Err(selErr).Msg("Error selecting tenant")
		return "", fmt.Errorf("error selecting tenant: %w", selErr)
	}
	for _, tenant := range availableTenants {
		if tenant.Name == selectedTenantName {
			tenantID = tenant.ID
			break
		}
	}

	return tenantID, nil
}

type clientIDResponse struct {
	ClientID string `json:"client_id"`
}

func GetClientID(ctx workflow.InvocationContext, tenantID string) (string, error) {
	client := ctx.GetNetworkAccess().GetHttpClient()

	url := fmt.Sprintf("%s/hidden/tenants/%s/mcp-scan/push-key?version=2025-08-28", ctx.GetConfiguration().GetString(configuration.API_URL), tenantID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("failed to create client id request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform client id request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return "", fmt.Errorf("forbidden: insufficient permissions to access tenant %s", tenantID)
		case http.StatusUnauthorized:
			return "", fmt.Errorf("unauthorized: authentication token is invalid or expired")
		default:
			return "", fmt.Errorf("unexpected status when requesting client id: %s", resp.Status)
		}
	}

	var body clientIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("failed to decode client id response: %w", err)
	}

	if !utils.IsValidUUID(body.ClientID) {
		return "", fmt.Errorf("received invalid client id from API")
	}

	return body.ClientID, nil
}
