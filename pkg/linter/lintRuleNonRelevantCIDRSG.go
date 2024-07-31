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
	return "rules of security groups that references CIDRs not in the relevant VPC address range"
}

func (lint *ruleNonRelevantCIDRSGLint) check() error {
	rulesNonRelevantCIDRFound, err := findRuleNonRelevantCIDR(lint.configs, vpcmodel.SecurityGroupLayer)
	if err != nil {
		return err
	}
	for i := range rulesNonRelevantCIDRFound {
		lint.addFinding(&rulesNonRelevantCIDRFound[i])
	}
	return nil
}
