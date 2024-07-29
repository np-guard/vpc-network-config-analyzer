/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleNonRelevantCIDRNACLName = "rules-referring-non-relevant-CIDRs-NACLs"

// ruleNonRelevantCIDRNACLLint: NACL rules that are references CIDRs not in the vpc
type ruleNonRelevantCIDRNACLLint struct {
	basicLinter
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleNonRelevantCIDRSGLint
// ////////////////////////////////////////////////////////
func (lint *ruleNonRelevantCIDRNACLLint) lintName() string {
	return ruleNonRelevantCIDRNACLName
}

func (lint *ruleNonRelevantCIDRNACLLint) lintDescription() string {
	return "rules of network ACLs that references CIDRs not in the relevant VPC address range"
}

func (lint *ruleNonRelevantCIDRNACLLint) check() error {
	rulesNonRelevantCIDRFound, err := findRuleNonRelevantCIDR(lint.configs, vpcmodel.NaclLayer)
	if err != nil {
		return err
	}
	for _, ruleNonRelevantCIDRFound := range rulesNonRelevantCIDRFound {
		lint.addFinding(&ruleNonRelevantCIDRFound)
	}
	return nil
}
