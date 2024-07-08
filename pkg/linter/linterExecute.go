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
func LinterExecute(configsMap map[string]*vpcmodel.VPCConfig) (issueFound bool, resString string) {
	for _, config := range configsMap {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		blinter := basicLinter{
			config: config,
		}
		linters := []linter{
			&filterRuleSplitSubnet{basicLinter: blinter},
		}
		header := "\nlinting results for " + config.VPC.Name()
		underline := strings.Repeat("~", len(header))
		resString += header + "\n" + underline + "\n\n"
		for _, thisLinter := range linters {
			lintIssues, err := thisLinter.check()
			if err != nil {
				fmt.Printf("Lint %s got an error %s. Skipping this lint\n", thisLinter.getName(), err.Error())
				continue
			}
			if len(lintIssues) == 0 {
				resString += fmt.Sprintf("no lint %s issues\n", thisLinter.getName())
				continue
			} else {
				issueFound = true
				resString += fmt.Sprintf("%s%s\n", thisLinter.getName(), issues) +
					strings.Repeat("-", len(thisLinter.getName())+len(issues)) + "\n" +
					strings.Join(lintIssues, "")
			}
		}
	}
	fmt.Printf("%v", resString)
	return issueFound, resString
}
