package mcpscan

import "github.com/spf13/pflag"

const (
	flagSetName      = "mcp-scan"
	FlagExperimental = "experimental"
	FlagClientID     = "client-id"
	FlagTenantID     = "tenant-id"
	FlagJSON         = "json"
	FlagSkills       = "skills"
	FlagNoUpload     = "no-upload"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)
	flagSet.Bool(FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagSet.String(FlagClientID, "", "Client ID")
	flagSet.String(FlagTenantID, "", "Tenant ID")
	flagSet.Bool(FlagJSON, false, "Output in JSON format")
	flagSet.String(FlagSkills, "", "Scan skills beyond mcp servers. Can be used as a boolean flag or with a folder path.")
	flagSet.Lookup(FlagSkills).NoOptDefVal = "true"
	flagSet.Bool(FlagNoUpload, false, "Do not upload the scan results to the Evo")
	return flagSet
}
