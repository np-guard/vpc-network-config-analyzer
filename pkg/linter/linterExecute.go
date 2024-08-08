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

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const issues = "issues:"
const delimBetweenLintsChars = 200

// linterGenerator is a function that generate a linter.
// we need a list of generators, and their names, so we holds a map from a linter name to its generator.
// when creating a new linter, this is the list of linters that should be updated:
type linterGenerator func(string, map[string]*vpcmodel.VPCConfig, map[string]*vpcmodel.VPCConnectivity) linter

var linterGenerators = map[string]linterGenerator{
	"rules-splitting-subnets-NACLS":            newFilterRuleSplitSubnetLintNACL,
	"rules-splitting-subnets-SecurityGroups":   newFilterRuleSplitSubnetLintSG,
	"overlapping-subnets":                      newOverlappingSubnetsLint,
	"redundant tables":                         newRedundantTablesLint,
	"rules-referring-non-relevant-CIDRs-SG":    newRuleNonRelevantCIDRSGLint,
	"rules-referring-non-relevant-CIDRs-NACLs": newRuleNonRelevantCIDRNACLLint,
	"blocked-TCP-response":                     newBlockedTCPResponseLint,
}

func ValidLintersNames() string {
	return strings.Join(common.MapKeys(linterGenerators), ",")
}
func IsValidLintersNames(name string) bool {
	_, ok := linterGenerators[name]
	return ok
}
func generateLinters(configs map[string]*vpcmodel.VPCConfig, nodeConn map[string]*vpcmodel.VPCConnectivity) []linter {
	res := make([]linter, len(linterGenerators))
	i := 0
	for name, generator := range linterGenerators {
		res[i] = generator(name, configs, nodeConn)
		i++
	}
	return res
}

func computeConnectivity(configs map[string]*vpcmodel.VPCConfig) (map[string]*vpcmodel.VPCConnectivity, error) {
	nodesConn := map[string]*vpcmodel.VPCConnectivity{}
	for uid, vpcConfig := range configs {
		nodesConnThisCfg, err := vpcConfig.GetVPCNetworkConnectivity(false, true)
		if err != nil {
			return nil, err
		}
		nodesConn[uid] = nodesConnThisCfg
	}
	return nodesConn, nil
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// LinterExecute executes linters one by one
func LinterExecute(configs map[string]*vpcmodel.VPCConfig,
	enableList, disableList []string) (issueFound bool, resString string, err error) {
	nodesConn, err := computeConnectivity(configs)
	if err != nil {
		return false, "", err
	}

	linters := generateLinters(configs, nodesConn)
	strPerLint := []string{}
	for _, thisLinter := range linters {
		name := thisLinter.lintName()
		enable := thisLinter.enableByDefault()
		enable = enable || slices.Contains(enableList, name)
		enable = enable && !slices.Contains(disableList, name)
		if !enable {
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
