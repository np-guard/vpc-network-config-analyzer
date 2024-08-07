/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// ruleNonRelevantCIDRNACLLint: NACL rules that are references CIDRs not in the vpc

func newRuleNonRelevantCIDRNACLLint(name string, configs map[string]*vpcmodel.VPCConfig,
	nodesConn map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "rules of network ACLs that references CIDRs not in the relevant VPC address range",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findRuleNonRelevantCIDR}
}
