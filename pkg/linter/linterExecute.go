package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
// todo: handle multiConfig
func LinterExecute(config *vpcmodel.VPCConfig) (bool, string) {
	blinter := basicLinter{
		config: config,
	}
	linters := []linter{
		&filterRuleSplitSubnet{basicLinter: blinter},
	}

	resString := fmt.Sprintf("lint:\n=====\n\n")
	for _, thisLinter := range linters {
		lintIssues, err := thisLinter.check()
		if err != nil {
			fmt.Printf("Lint %s got an error %s. Skipping this lint\n", thisLinter.getName(), err.Error())
			continue
		}
		if len(lintIssues) == 0 {
			fmt.Printf("no lint %s issues\n", thisLinter.getName())
			continue
		}
		resString = fmt.Sprintf("%s issues:\n", thisLinter.getName()) +
			fmt.Sprintf("%s\n", strings.Repeat("~", len(thisLinter.getName())+8)) +
			fmt.Sprintf(strings.Join(lintIssues, ""))
	}
	fmt.Printf(resString)
	return true, resString
}