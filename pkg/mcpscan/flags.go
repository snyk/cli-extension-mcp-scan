package mcpscan

import "github.com/spf13/pflag"

const (
	flagSetName = "mcp-scan"
)

const (
	FlagExperimental = "experimental"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)
	flagSet.Bool(FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagSet.String("client-id", "", "Client ID")
	flagSet.String("tenant-id", "", "Tenant ID")

	return flagSet
}
