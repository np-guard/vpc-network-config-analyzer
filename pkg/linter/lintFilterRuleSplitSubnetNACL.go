/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// filterRuleSplitSubnetLintNACL: NACL rules that are inconsistent w.r.t. subnets.
func newFilterRuleSplitSubnetLintNACL(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "rules of network ACLs implying different connectivity for different endpoints within a subnet",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findSplitRulesSubnet}
}
