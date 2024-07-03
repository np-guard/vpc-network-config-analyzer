package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
func LinterExecute(config *vpcmodel.VPCConfig) bool {
	blinter := basicLinter{
		config: config,
	}
	linters := []linter{
		&filterRuleSplitSubnet{basicLinter: blinter},
	}

	fmt.Printf("lint:\n=====\n\n")
	for _, thisLinter := range linters {
		lintIssues := thisLinter.check()
		if len(lintIssues) == 0 {
			fmt.Printf("no lint %s issues\n", thisLinter.getName())
			continue
		}
		fmt.Printf("%s issues:\n", thisLinter.getName())
		fmt.Printf("%s\n", strings.Repeat("~", len(thisLinter.getName())+8))
		fmt.Printf("\t" + strings.Join(lintIssues, "\n\t"))
	}
	return true
}
