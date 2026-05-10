package main

import (
	"fmt"
	"os"

	"github.com/mk6i/open-oscar-server/foodgroup"
)

func main() {
	results, err := foodgroup.Jimm060FullInfoPayloadAudit()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var failed bool
	for _, res := range results {
		if res.Err != nil {
			failed = true
			fmt.Printf("%s: FAIL: %v\n", res.Name, res.Err)
			if res.PayloadHex != "" {
				fmt.Printf("%s: hex=%s\n", res.Name, res.PayloadHex)
			}
			for _, line := range res.Trace {
				fmt.Printf("  %s\n", line)
			}
			continue
		}
		fmt.Printf("%s: OK hex=%s\n", res.Name, res.PayloadHex)
		for _, line := range res.Trace {
			fmt.Printf("  %s\n", line)
		}
	}

	if failed {
		os.Exit(1)
	}
}
