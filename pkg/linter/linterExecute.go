/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const delimBetweenLintsChars = 200

// linterGenerator is a function that generate a linter.
// we need a list of generators, and their names, so we holds a map from a linter name to its generator.
// when creating a new linter, this is the list of linters that should be updated:
type linterGenerator func(string, map[string]*vpcmodel.VPCConfig, map[string]*vpcmodel.VPCConnectivity) linter

var linterGenerators = map[string]linterGenerator{
	"nacl-split-subnet":           newNACLSplitSubnet,
	"sg-split-subnet":             newSGSplitSubnet,
	"subnet-cidr-overlap":         newSubnetCIDROverlap,
	"nacl-unattached":             newNACLUnattachedLint,
	"sg-unattached":               newSGUnattachedLint,
	"sg-rule-cidr-out-of-range":   newSGRuleCIDROutOfRange,
	"nacl-rule-cidr-out-of-range": newNACLRuleCIDROutOfRange,
	"tcp-response-blocked":        newTCPResponseBlocked,
	"nacl-rule-shadowed":          newNACLRuleShadowed,
	"sg-rule-implied":             newSGRuleImplied,
}

func ValidLintersNames() string {
	return strings.Join(slices.Collect(maps.Keys(linterGenerators)), ",")
}
func IsValidLintersNames(name string) bool {
	_, ok := linterGenerators[name]
	return ok
}
func generateLinters(configs map[string]*vpcmodel.VPCConfig, nodeConn map[string]*vpcmodel.VPCConnectivity) Linters {
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

// LinterExecute performs the lint analysis and then prints the string result; should be redundant once lint is
// integrated in the general flow
func LinterExecute(configs map[string]*vpcmodel.VPCConfig, printAllFindings bool,
	enableList, disableList []string) (issueFound bool, resString string, err error) {
	linters, err := linterAnalysis(configs, enableList, disableList)
	if err != nil {
		return false, "", err
	}
	resString = linters.String(printAllFindings)
	fmt.Println(resString)
	return issueFound, resString, nil
}

// linterAnalysis executes linters one by one and collects their results
func linterAnalysis(configs map[string]*vpcmodel.VPCConfig, enableList, disableList []string) (linters Linters, err error) {
	nodesConn, err := computeConnectivity(configs)
	if err != nil {
		return nil, err
	}

	linters = generateLinters(configs, nodesConn)
	for _, thisLinter := range linters {
		name := thisLinter.lintName()
		enable := thisLinter.enableByDefault()
		enable = enable || slices.Contains(enableList, name)
		enable = enable && !slices.Contains(disableList, name)
		if !enable {
			continue
		}
		err := thisLinter.check()
		if err != nil {
			return nil, err
		}
	}
	return linters, nil
}

func (linters Linters) String(printAllFindings bool) (resString string) {
	strPerLint := []string{}
	for _, thisLinter := range linters {
		lintFindings := thisLinter.getFindings()
		if len(lintFindings) > 0 {
			thisLintStr := thisLinter.string(thisLinter.lintDescription(), printAllFindings)
			strPerLint = append(strPerLint, thisLintStr)
		}
	}
	sort.Strings(strPerLint)
	delimBetweenLints := strings.Repeat("_", delimBetweenLintsChars)
	resString = strings.Join(strPerLint, "\n"+delimBetweenLints+"\n\n")
	return resString
}
