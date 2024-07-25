/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleNonRelevantCIDRSGName = "rules-referring-non-relevant-CIDRs-SG"

// ruleNonRelevantCIDRSGLint: SG rules that are references CIDRs not in the vpc
type ruleNonRelevantCIDRSGLint struct {
	basicLinter
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleNonRelevantCIDRSGLint
// ////////////////////////////////////////////////////////
func (lint *ruleNonRelevantCIDRSGLint) lintName() string {
	return ruleNonRelevantCIDRSGName
}

func (lint *ruleNonRelevantCIDRSGLint) lintDescription() string {
	return "rules of network ACLs that references CIDRs not in the relevant VPC address range"
}

func (lint *ruleNonRelevantCIDRSGLint) check() error {
	rulesNonRelevantCIDRFound, err := findRuleNonRelevantCIDR(lint.configs, vpcmodel.NaclLayer)
	if err != nil {
		return err
	}
	for _, ruleNonRelevantCIDRFound := range rulesNonRelevantCIDRFound {
		lint.addFinding(&ruleNonRelevantCIDRFound)
	}
	return nil
}
