package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

type filterRuleSplitSubnet struct {
	basicLinter
	finding splitRulesInLayers
}

// todo: 1. check what is the presentation of cidr
//       2. add documentation

type ruleOfFilter struct {
	filterIndx int
	RuleIndx   int
}

type splittedSubnet struct {
	subnet *vpcmodel.Subnet
	cidrs  []string
}

type splitRuleSubnet struct {
	rule     ruleOfFilter
	splitted []splittedSubnet
}

type splitRulesInLayers map[string][]splitRuleSubnet

func (lint *filterRuleSplitSubnet) check() []string {
	// todo getFilterTrafficResourceOfKind from vpcmodel needs to be exported
	return []string{"test1", "test2", "test3"}
}

func (lint *filterRuleSplitSubnet) getName() string {
	return "filterRuleSplitSubnet"
}

func (lint *filterRuleSplitSubnet) getFindings() []any {
	return nil
}
