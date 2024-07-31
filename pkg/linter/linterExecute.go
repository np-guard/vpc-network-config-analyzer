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

// LinterExecute executes linters one by one
// todo: mechanism for disabling/enabling lint checks
func LinterExecute(configs map[string]*vpcmodel.VPCConfig) (issueFound bool, resString string, err error) {
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
