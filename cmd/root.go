package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/acardace/fips-detect/pkg/fips"
	"github.com/spf13/cobra"
)

var printSymbols = map[bool]string{
	true:  "Yes!",
	false: "No",
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "fips-detect [GO_BINARY]",
	Short: "Inspect your Go binary to check if it's FIPS ready",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		goBinary := ""
		if len(args) > 0 {
			goBinary = args[0]
		}
		fipsReport := fips.FipsSystemCheck(goBinary)

		jsonToggle, err := cmd.Flags().GetBool("json")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if jsonToggle {
			jsonBytes, err := json.Marshal(fipsReport)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Stdout.Write(jsonBytes)
		} else {
			fmt.Println("FIPS System Report")
			printSysReport(fipsReport.FipsMode, "Host running in FIPS mode")
			printSysReport(fipsReport.CryptoLibsFips, "FIPS-capable crypto library")
			printSysReport(fipsReport.FipsCompatibleGoBinary, "FIPS-capable Go binary")
		}
	},
}

func printSysReport(sysReport *fips.SystemReport, msg string) {
	fmt.Printf("%s ...%s\n", msg, printSymbols[sysReport.Value])
	if sysReport.Err != nil {
		fmt.Printf("   %s\n", sysReport.Err)
	}
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().BoolP("json", "j", false, "output in JSON format")
}
