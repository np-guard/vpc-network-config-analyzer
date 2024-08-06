/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const splitRuleSubnetNACLName = "rules-splitting-subnets-NACLS"
const splitRuleSubnetNACLDescription = "rules of network ACLs implying different connectivity for different endpoints within a subnet"

// filterRuleSplitSubnetLintNACL: NACL rules that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnetLintNACL struct {
	filterLinter
}

func newFilterRuleSplitSubnetLintNACL(configs map[string]*vpcmodel.VPCConfig) *filterRuleSplitSubnetLintNACL {
	return &filterRuleSplitSubnetLintNACL{
		filterLinter{
			basicLinter{
				configs:     configs,
				name:        splitRuleSubnetNACLName,
				description: splitRuleSubnetNACLDescription,
			},
			vpcmodel.NaclLayer,
			findSplitRulesSubnet}}
}
