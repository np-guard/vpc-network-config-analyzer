/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const splitRuleSubnetSGName = "rules-splitting-subnets-SecurityGroups"
const splitRuleSubnetSGDescription = "rules of security groups implying different connectivity for different endpoints within a subnet"

// filterRuleSplitSubnetLintSG: SG rules that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnetLintSG struct {
	filterLinter
}

func newFilterRuleSplitSubnetLintSG(configs map[string]*vpcmodel.VPCConfig) *filterRuleSplitSubnetLintSG {
	return &filterRuleSplitSubnetLintSG{
		filterLinter{
			basicLinter{
				configs:     configs,
				name:        splitRuleSubnetSGName,
				description: splitRuleSubnetSGDescription,
			},
			vpcmodel.SecurityGroupLayer,
			findSplitRulesSubnet}}
}
