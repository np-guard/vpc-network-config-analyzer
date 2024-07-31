/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

const ruleRedundantSGName = "rules-redundant-SG"

// ruleRedundantSGLint: SG rules that are implied by other rules
type ruleRedundantSGLint struct {
	basicLinter
}

// /////////////////////////////////////////////////////////
// lint interface implementation for ruleRedundantSGLint
// ////////////////////////////////////////////////////////
func (lint *ruleRedundantSGLint) lintName() string {
	return ruleRedundantSGName
}

func (lint *ruleRedundantSGLint) lintDescription() string {
	return "security group rules that are implied by other rules"
}

func (lint *ruleRedundantSGLint) check() error {
	rulesRedundantSGFound, err := findRuleSyntacticRedundant(lint.configs, vpcmodel.SecurityGroupLayer)
	if err != nil {
		return err
	}
	for _, ruleRedundantSGFound := range rulesRedundantSGFound {
		lint.addFinding(&ruleRedundantSGFound)
	}
	return nil
}
