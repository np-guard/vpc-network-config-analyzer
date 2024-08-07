/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const issues = "issues:"
const delimBetweenLintsChars = 200

func GetLintersNames() map[string]bool {
	return nil //todo
}

// LinterExecute executes linters one by one
func LinterExecute(configs map[string]*vpcmodel.VPCConfig,
	enableList, disableList []string) (issueFound bool, resString string, err error) {
	nodesConn := map[string]*vpcmodel.VPCConnectivity{}
	for uid, vpcConfig := range configs {
		nodesConnThisCfg, err := vpcConfig.GetVPCNetworkConnectivity(false, true)
		if err != nil {
			return false, "", err
		}
		nodesConn[uid] = nodesConnThisCfg
	}
	linters := []linter{
		newFilterRuleSplitSubnetLintNACL(configs),
		newFilterRuleSplitSubnetLintSG(configs),
		newOverlappingSubnetsLint(configs),
		newRedundantTablesLint(configs),
		newRuleNonRelevantCIDRSGLint(configs),
		newRuleNonRelevantCIDRNACLLint(configs),
		newBlockedTCPResponseLint(configs, nodesConn),
	}
	strPerLint := []string{}
	for _, thisLinter := range linters {
		name := thisLinter.lintName()
		// enable :=  slice.Contains(enableList,name) 
		switch {
		case slices.Contains(enableList,name):
		case slices.Contains(disableList,name), !thisLinter.enableByDefault():
			fmt.Printf("%q linter disabled.\n\n", thisLinter.lintDescription())
			continue
		}
		thisLintStr := ""
		err := thisLinter.check()
		if err != nil {
			return false, "", err
		}
		lintFindings := thisLinter.getFindings()
		if len(lintFindings) == 0 {
			thisLintStr = fmt.Sprintf("no lint %q issues\n", thisLinter.lintDescription())
		} else {
			issueFound = true
			thisLintStr = thisLinter.string(thisLinter.lintDescription())
		}
		strPerLint = append(strPerLint, thisLintStr)
	}
	sort.Strings(strPerLint)
	delimBetweenLints := strings.Repeat("_", delimBetweenLintsChars)
	resString = strings.Join(strPerLint, "\n"+delimBetweenLints+"\n\n")
	fmt.Println(resString)
	return issueFound, resString, nil
}
