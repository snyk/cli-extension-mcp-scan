package utils

import (
	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func CheckAuthentication(ctx workflow.InvocationContext) string {
	config := ctx.GetConfiguration()
	logger := ctx.GetEnhancedLogger()
	token := config.GetString(configuration.AUTHENTICATION_TOKEN)
	if token != "" {
		ctx.GetEnhancedLogger().Info().Msg("API Token found")
		return token
	}

	token = config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	if token != "" {
		logger.Info().Msg("Bearer Token found")
		return token
	}

	oauthToken, err := auth.GetOAuthToken(config)
	if err == nil && oauthToken != nil && oauthToken.AccessToken != "" {
		logger.Info().Msg("OAuth Token found")
		return oauthToken.AccessToken
	}

	return ""
}

func IsValidUUID(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}
