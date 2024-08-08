/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// ruleRedundantNACLLint: NACL rules that are overruled by higher priority rules
func newRuleShadowedNACLLint(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "rules of network ACLs that are shadowed by higher priority rules",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findRuleSyntacticRedundant}
}
