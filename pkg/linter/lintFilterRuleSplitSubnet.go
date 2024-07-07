package linter

import (
	"fmt"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// filterRuleSplitSubnet: rules of filters that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnet struct {
	basicLinter
	finding []splitRuleSubnet
}

// a rule with the list of subnets it splits
type splitRuleSubnet struct {
	rule         vpcmodel.RuleOfFilter
	splitSubnets []vpcmodel.Subnet
}

// list all splitting rules under the name of the table
func (lint *filterRuleSplitSubnet) check() ([]string, error) {
	findingRes := []splitRuleSubnet{}
	strRes := []string{}
	for _, layer := range vpcmodel.FilterLayers {
		thisLayerName := "Network acl"
		if layer == vpcmodel.SecurityGroupLayer {
			thisLayerName = "Security group"
		}
		thisLayerSplit := []splitRuleSubnet{}
		filterLayer := lint.config.GetFilterTrafficResourceOfKind(layer)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for _, rule := range rules {
			subnetsSplitByRule := []vpcmodel.Subnet{}
			for _, subnet := range lint.config.Subnets {
				splitSubnet, err := ruleSplitSubnet(subnet, rule.IPBlocks)
				if err != nil {
					return nil, err
				}
				if splitSubnet {
					subnetsSplitByRule = append(subnetsSplitByRule, subnet)
					strRes = append(strRes, fmt.Sprintf("%s %s rule indexed %d splits subnet %s with cidr %s. "+
						"Splitting rule details: %s", thisLayerName, rule.FilterName, rule.RuleIndx, subnet.Name(),
						subnet.CIDR(), rule.RuleDesc))
				}
			}
			if len(subnetsSplitByRule) > 0 {
				thisLayerSplit = append(thisLayerSplit,
					splitRuleSubnet{rule: rule, splitSubnets: subnetsSplitByRule})
			}
		}
		if len(thisLayerSplit) > 0 {
			findingRes = append(findingRes, thisLayerSplit...)
		}
	}
	lint.finding = findingRes
	return strRes, nil
}

// given a subnet and IPBlocks mentioned in a rule, returns the list
func ruleSplitSubnet(subnet vpcmodel.Subnet, ruleIPBlocks []*ipblock.IPBlock) (bool, error) {
	cidr := subnet.CIDR()
	subnetCidrIPBlock, err := ipblock.FromCidr(cidr)
	if err != nil {
		return false, err
	}
	for _, ruleIPBlock := range ruleIPBlocks {
		if ruleIPBlock.Overlap(subnetCidrIPBlock) && !subnetCidrIPBlock.ContainedIn(ruleIPBlock) {
			return true, nil
		}
	}
	return false, nil
}

func (lint *filterRuleSplitSubnet) getName() string {
	return "filterRuleSplitSubnet"
}

// todo
func (lint *filterRuleSplitSubnet) getFindings() []any {
	return nil
}
