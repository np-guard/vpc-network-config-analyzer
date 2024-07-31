/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleRedundantNACLName = "rules-redundant-NACL"

// ruleRedundantNACLLint: NACL rules that are overruled by higher priority rules
type ruleRedundantNACLLint struct {
	basicLinter
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleNonRelevantCIDRSGLint
// ////////////////////////////////////////////////////////
func (lint *ruleRedundantNACLLint) lintName() string {
	return ruleRedundantNACLName
}

func (lint *ruleRedundantNACLLint) lintDescription() string {
	return "rules of network ACLs that are shadowed by higher priority rules"
}

func (lint *ruleRedundantNACLLint) check() error {
	rulesRedundantNACLFound, err := findRuleSyntacticRedundant(lint.configs, vpcmodel.NaclLayer)
	if err != nil {
		return err
	}
	for _, ruleRedundantNACLFound := range rulesRedundantNACLFound {
		lint.addFinding(&ruleRedundantNACLFound)
	}
	return nil
}
