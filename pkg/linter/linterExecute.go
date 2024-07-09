/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const issues = "issues:"

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
func LinterExecute(configs map[string]*vpcmodel.VPCConfig) (issueFound bool, resString string, err error) {
	blinter := basicLinter{
		configs: configs,
	}
	linters := []linter{
		&filterRuleSplitSubnet{basicLinter: blinter},
	}
	strPerLint := []string{}
	for _, thisLinter := range linters {
		thisLintStr := ""
		lintOK, err := thisLinter.check()
		if err != nil {
			return false, "", err
		}
		if lintOK {
			thisLintStr = fmt.Sprintf("no lint %q issues\n", thisLinter.lintDescription())
		} else {
			issueFound = true
			thisLintStr = thisLinter.string()
		}
		strPerLint = append(strPerLint, thisLintStr)
	}
	sort.Strings(strPerLint)
	resString = strings.Join(strPerLint, "")
	fmt.Println(resString)
	return issueFound, resString, nil
}
