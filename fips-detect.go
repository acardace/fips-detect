package main

import (
	"fmt"
	"os"

	"github.com/acardace/fips-detect/pkg/fips"
)

var printSymbols = map[bool]string{
	true:  "Yes!",
	false: "No",
}

func printSysReport(sysReport *fips.SystemReport, msg string) {
	fmt.Printf("%s ...%s\n", msg, printSymbols[sysReport.Value])
	if sysReport.Err != nil {
		fmt.Printf("   %s\n", sysReport.Err)
	}
}

func main() {
	goBinary := ""
	if len(os.Args) > 1 {
		goBinary = os.Args[1]
	}
	fipsReport := fips.FipsSystemCheck(goBinary)

	fmt.Println("FIPS System Report")
	printSysReport(fipsReport.FipsMode, "Host running in FIPS mode")
	printSysReport(fipsReport.CryptoLibsFips, "FIPS-capable crypto library")
	printSysReport(fipsReport.FipsCompatibleGoBinary, "FIPS-capable Go binary")
}
