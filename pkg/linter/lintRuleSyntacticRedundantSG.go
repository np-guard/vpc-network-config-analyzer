/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// newRuleRedundantSGRuleLint: SG rules that are implied by other rules
func newRuleRedundantSGRuleLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "security group rules that are implied by other rules",
			enable:      true,
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findRuleSyntacticRedundant}
}
