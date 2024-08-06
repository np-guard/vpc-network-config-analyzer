/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// filterRuleSplitSubnetLintNACL: NACL rules that are inconsistent w.r.t. subnets.
func newFilterRuleSplitSubnetLintNACL(configs map[string]*vpcmodel.VPCConfig) *filterLinter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        "rules-splitting-subnets-NACLS",
			description: "rules of network ACLs implying different connectivity for different endpoints within a subnet",
		},
		layer:          vpcmodel.NaclLayer,
		filterFindings: findSplitRulesSubnet}
}
