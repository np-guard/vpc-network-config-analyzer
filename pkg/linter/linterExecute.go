/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const issues = " issues:"

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
	resString = "linting results for " + config.VPC.Name()
	underline := strings.Repeat("~", len(resString))
	resString += "\n" + underline + "\n\n"
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
		resString += fmt.Sprintf("%s%s\n", thisLinter.getName(), issues) +
			strings.Repeat("-", len(thisLinter.getName())+len(issues)) + "\n" +
			strings.Join(lintIssues, "")
	}
	fmt.Printf("%v", resString)
	return issueFound, resString
}
