package mcpscan

import "github.com/spf13/pflag"

const (
	flagSetName      = "mcp-scan"
	FlagExperimental = "experimental"
	FlagClientID     = "client-id"
	FlagTenantID     = "tenant-id"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)
	flagSet.Bool(FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagSet.String(FlagClientID, "", "Client ID")
	flagSet.String(FlagTenantID, "", "Tenant ID")

	return flagSet
}
