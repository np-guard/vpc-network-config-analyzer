/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const SplitRuleSubnetSGName = "rules-splitting-subnets-SecurityGroups"

// filterRuleSplitSubnetLintSG: SG rules that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnetLintSG struct {
	basicLinter
}

// //////////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnetLintSG
// /////////////////////////////////////////////////////////////
func (lint *filterRuleSplitSubnetLintSG) lintName() string {
	return SplitRuleSubnetSGName
}

func (lint *filterRuleSplitSubnetLintSG) lintDescription() string {
	return "rules of security groups implying different connectivity for different endpoints within a subnet"
}

func (lint *filterRuleSplitSubnetLintSG) check() error {
	rulesSplitSubnetsFound, err := findSplitRulesSubnet(lint.configs, vpcmodel.SecurityGroupLayer)
	if err != nil {
		return err
	}
	for i := range rulesSplitSubnetsFound {
		lint.addFinding(&rulesSplitSubnetsFound[i])
	}
	return nil
}
