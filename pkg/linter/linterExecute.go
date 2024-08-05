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
const delimBetweenLintsChars = 200

func GetLintersNames() map[string]bool {
	return map[string]bool{blockedTCPResponse: true, splitRuleSubnetNACLName: true, splitRuleSubnetSGName: true,
		overlappingSubnetsName: true, ruleNonRelevantCIDRNACLName: true, redundantTablesName: true,
		ruleNonRelevantCIDRSGName: true}
}

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
func LinterExecute(configs map[string]*vpcmodel.VPCConfig,
	enableLints, disableLints string) (issueFound bool, resString string, err error) {
	enableLinters := // mechanism for enabling and disabling linters
		map[string]bool{blockedTCPResponse: true, splitRuleSubnetNACLName: true, splitRuleSubnetSGName: true,
			overlappingSubnetsName: true, ruleNonRelevantCIDRNACLName: true, redundantTablesName: true,
			ruleNonRelevantCIDRSGName: true}
	{
	}
	// enable and disable as per the cli
	enableList := strings.Split(enableLints, ",")
	disableList := strings.Split(disableLints, ",")
	for _, disable := range disableList {
		enableLinters[disable] = false
	}
	for _, enable := range enableList {
		enableLinters[enable] = true
	}
	nodesConn := map[string]*vpcmodel.VPCConnectivity{}
	for uid, vpcConfig := range configs {
		nodesConnThisCfg, err := vpcConfig.GetVPCNetworkConnectivity(false, true)
		if err != nil {
			return false, "", err
		}
		nodesConn[uid] = nodesConnThisCfg
	}
	basicLint := basicLinter{
		configs: configs,
	}
	connLint := connectionLinter{basicLint, nodesConn}
	linters := []linter{
		&filterRuleSplitSubnetLintNACL{basicLinter: basicLint},
		&filterRuleSplitSubnetLintSG{basicLinter: basicLint},
		&overlappingSubnetsLint{basicLinter: basicLint},
		&redundantTablesLint{basicLinter: basicLint},
		&ruleNonRelevantCIDRSGLint{basicLinter: basicLint},
		&ruleNonRelevantCIDRNACLLint{basicLinter: basicLint},
		&blockedTCPResponseLint{connectionLinter: connLint},
	}
	strPerLint := []string{}
	for _, thisLinter := range linters {
		if !enableLinters[thisLinter.lintName()] {
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
