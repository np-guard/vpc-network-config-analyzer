/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleNonRelevantCIDRNACLName = "rules-referring-non-relevant-CIDRs-NACLs"
const ruleNonRelevantCIDRNACLDescription = "rules of network ACLs that references CIDRs not in the relevant VPC address range"
// ruleNonRelevantCIDRNACLLint: NACL rules that are references CIDRs not in the vpc
type ruleNonRelevantCIDRNACLLint struct {
	basicLinter
}

func newRuleNonRelevantCIDRNACLLint(configs map[string]*vpcmodel.VPCConfig) *ruleNonRelevantCIDRNACLLint {
	return &ruleNonRelevantCIDRNACLLint{
		basicLinter{
			configs:     configs,
			name:        ruleNonRelevantCIDRNACLName,
			description: ruleNonRelevantCIDRNACLDescription,
		}}
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleNonRelevantCIDRSGLint
// ////////////////////////////////////////////////////////
func (lint *ruleNonRelevantCIDRNACLLint) check() error {
	rulesNonRelevantCIDRFound, err := findRuleNonRelevantCIDR(lint.configs, vpcmodel.NaclLayer)
	if err != nil {
		return err
	}
	for _,f := range rulesNonRelevantCIDRFound {
		lint.addFinding(f)
	}
	return nil
}
