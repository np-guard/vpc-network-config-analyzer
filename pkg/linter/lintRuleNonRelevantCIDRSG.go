/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleNonRelevantCIDRSGName = "rules-referring-non-relevant-CIDRs-SG"
const ruleNonRelevantCIDRSGDescription = "rules of security groups that references CIDRs not in the relevant VPC address range"
// ruleNonRelevantCIDRSGLint: SG rules that are references CIDRs not in the vpc
type ruleNonRelevantCIDRSGLint struct {
	basicLinter
}
func newRuleNonRelevantCIDRSGLint(configs map[string]*vpcmodel.VPCConfig) *ruleNonRelevantCIDRSGLint {
	return &ruleNonRelevantCIDRSGLint{
		basicLinter{
			configs:     configs,
			name:        ruleNonRelevantCIDRSGName,
			description: ruleNonRelevantCIDRSGDescription,
		}}
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleNonRelevantCIDRSGLint
// ////////////////////////////////////////////////////////

func (lint *ruleNonRelevantCIDRSGLint) check() error {
	rulesNonRelevantCIDRFound, err := findRuleNonRelevantCIDR(lint.configs, vpcmodel.SecurityGroupLayer)
	if err != nil {
		return err
	}
	for _, f := range rulesNonRelevantCIDRFound {
		lint.addFinding(f)
	}
	return nil
}
