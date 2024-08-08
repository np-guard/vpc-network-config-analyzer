/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// ruleNonRelevantCIDRSGLint: SG rules that are references CIDRs not in the vpc
func newRuleNonRelevantCIDRSGLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "rules of security groups that references CIDRs not in the relevant VPC address range",
			enable:      true,
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findRuleNonRelevantCIDR}
}
