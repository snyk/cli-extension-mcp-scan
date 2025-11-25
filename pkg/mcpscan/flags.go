package mcpscan

import "github.com/spf13/pflag"

const (
	flagSetName = "mcp-scan"
)

const (
	FlagOpt  = "opt"
	FlagExperimental = "experimental"
	FlagHelp = "help"
)

func getFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet(flagSetName, pflag.ExitOnError)
	flagSet.Bool(FlagExperimental, false, "This is an experiment feature that will contain breaking changes in future revisions")
	flagSet.Bool(FlagOpt, false, "My option")
	flagSet.Bool(FlagHelp, false, "Help")
	

	return flagSet
}
