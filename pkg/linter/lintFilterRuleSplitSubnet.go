package linter

import (
	"fmt"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

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

func (lint *filterRuleSplitSubnet) check() ([]string, error) {
	for _, layer := range vpcmodel.FilterLayers {
		filterLayer := lint.config.GetFilterTrafficResourceOfKind(layer)
		fmt.Printf("filterLayer %s\n~~~~~~~~~~~~~~~~~\n", layer)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for _, rule := range rules { // todo tmp
			fmt.Printf("filter: %s rule %d, %s ", rule.FilterName, rule.RuleIndx, rule.RuleDesc)
			fmt.Println("IPBlocks:")
			for _, block := range rule.IPBlocks {
				fmt.Printf("\t%s\n", block.String())
			}
		}
	}
	return nil, nil
}

func (lint *filterRuleSplitSubnet) getName() string {
	return "filterRuleSplitSubnet"
}

func (lint *filterRuleSplitSubnet) getFindings() []any {
	return nil
}

// todo getFilterTrafficResourceOfKind export
