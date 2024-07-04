package linter

import "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"

// filterRuleSplitSubnet: rules of filters that are inconsistent w.r.t. subnets.

type filterRuleSplitSubnet struct {
	basicLinter
	finding splitRulesInLayers
}

// a subnets and a list of relevant filters
type subnetCidrs struct {
	subnet *vpcmodel.Subnet
	cidrs  []string
}

// a rule with the list of subnet's in splits
type splitRuleSubnet struct {
	rule     vpcmodel.RuleOfFilter
	splitted []subnetCidrs
}

// For each layer (SGLayer/NACLLayer) - list of splitting rules with splitted subnet's details
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

// todo getFilterTrafficResourceOfKind export
