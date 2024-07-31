/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const splitRuleSubnetNACLName = "rules-splitting-subnets-NACLS"

// filterRuleSplitSubnetLintNACL: NACL rules that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnetLintNACL struct {
	basicLinter
}

// /////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnetLint
// ////////////////////////////////////////////////////////
func (lint *filterRuleSplitSubnetLintNACL) lintName() string {
	return splitRuleSubnetNACLName
}

func (lint *filterRuleSplitSubnetLintNACL) lintDescription() string {
	return "rules of network ACLs implying different connectivity for different endpoints within a subnet"
}

func (lint *filterRuleSplitSubnetLintNACL) check() error {
	rulesSplitSubnetsFound, err := findSplitRulesSubnet(lint.configs, vpcmodel.NaclLayer)
	if err != nil {
		return err
	}
	for i := range rulesSplitSubnetsFound {
		lint.addFinding(&rulesSplitSubnetsFound[i])
	}
	return nil
}
