/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// filterRuleSplitSubnetLintSG: SG rules that are inconsistent w.r.t. subnets.
func newFilterRuleSplitSubnetLintSG(configs map[string]*vpcmodel.VPCConfig) *filterLinter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        "rules-splitting-subnets-SecurityGroups",
			description: "rules of security groups implying different connectivity for different endpoints within a subnet",
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findSplitRulesSubnet}
}
