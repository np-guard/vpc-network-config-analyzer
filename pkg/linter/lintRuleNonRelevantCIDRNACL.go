/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// ruleNonRelevantCIDRNACLLint: NACL rules that are references CIDRs not in the vpc

func newRuleNonRelevantCIDRNACLLint(configs map[string]*vpcmodel.VPCConfig) *filterLinter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        "rules-referring-non-relevant-CIDRs-NACLs",
			description: "rules of network ACLs that references CIDRs not in the relevant VPC address range",
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findRuleNonRelevantCIDR}
}
