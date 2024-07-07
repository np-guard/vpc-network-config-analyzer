package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
// todo: handle multiConfig
func LinterExecute(config *vpcmodel.VPCConfig) (issueFound bool, resString string) {
	blinter := basicLinter{
		config: config,
	}
	linters := []linter{
		&filterRuleSplitSubnet{basicLinter: blinter},
	}
	issueFound = false
	resString = "lint:\n=====\n\n"
	for _, thisLinter := range linters {
		lintIssues, err := thisLinter.check()
		if err != nil {
			fmt.Printf("Lint %s got an error %s. Skipping this lint\n", thisLinter.getName(), err.Error())
			continue
		}
		if len(lintIssues) == 0 {
			fmt.Printf("no lint %s issues\n", thisLinter.getName())
			continue
		} else {
			issueFound = true
		}
		resString = fmt.Sprintf("%s issues:\n", thisLinter.getName()) +
			strings.Repeat("~", len(thisLinter.getName())+8) +
			strings.Join(lintIssues, "")
	}
	fmt.Printf("%v", resString)
	return issueFound, resString
}
