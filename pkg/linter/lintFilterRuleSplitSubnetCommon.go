/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// a rule with the list of subnets it splits
type splitRuleSubnet struct {
	rule         vpcmodel.RuleOfFilter
	splitSubnets []vpcmodel.Subnet
}

////////////////////////////////////////////////////////////////////////////////////////////
// functionality used by both filterRuleSplitSubnetLintNACL and filterRuleSplitSubnetLintSG
////////////////////////////////////////////////////////////////////////////////////////////

func findSplitRulesSubnet(configs map[string]*vpcmodel.VPCConfig, filterLayerName string) (res []splitRuleSubnet, err error) {
	for uid := range configs {
		if configs[uid].IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		filterLayer := configs[uid].GetFilterTrafficResourceOfKind(filterLayerName)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for i1 := range rules {
			subnetsSplitByRule := []vpcmodel.Subnet{}
			for i2 := range configs[uid].Subnets {
				splitSubnet := ruleSplitSubnet(configs[uid].Subnets[i2], [2]*ipblock.IPBlock{rules[i1].SrcCidr, rules[i1].DstCidr})
				if splitSubnet {
					subnetsSplitByRule = append(subnetsSplitByRule, configs[uid].Subnets[i2])
				}
			}
			if len(subnetsSplitByRule) > 0 {
				res = append(res, splitRuleSubnet{rule: rules[i1], splitSubnets: subnetsSplitByRule})
			}
		}
	}
	return res, nil
}

// given a subnet and IPBlocks mentioned in a rule, returns true if the rules split any of the blocks
func ruleSplitSubnet(subnet vpcmodel.Subnet, ruleIPBlocks [2]*ipblock.IPBlock) bool {
	subnetCidrIPBlock := subnet.AddressRange()
	for i := range ruleIPBlocks {
		if ruleIPBlocks[i].Overlap(subnetCidrIPBlock) && !subnetCidrIPBlock.ContainedIn(ruleIPBlocks[i]) {
			return true
		}
	}
	return false
}

///////////////////////////////////////////////////////////
// finding interface implementation for splitRuleSubnet
//////////////////////////////////////////////////////////

func (finding *splitRuleSubnet) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.splitSubnets[0].VPC()}
}

func (finding *splitRuleSubnet) string() string {
	rule := finding.rule
	subnetsStrSlice := make([]string, len(finding.splitSubnets))
	for i := range finding.splitSubnets {
		subnetsStrSlice[i] = fmt.Sprintf("%s (%s)", finding.splitSubnets[i].Name(), finding.splitSubnets[i].CIDR())
	}
	subnetStr := strings.Join(subnetsStrSlice, ", ")
	if len(subnetsStrSlice) > 1 {
		subnetStr = "subnets " + subnetStr
	} else {
		subnetStr = "subnet " + subnetStr
	}
	return fmt.Sprintf("In VPC %s, %s %s rule's indexed %d splits %s. Splitting rule details: %s",
		finding.vpc()[0].Name(), finding.rule.Filter.LayerName, rule.Filter.FilterName, rule.RuleIndex, subnetStr,
		strings.ReplaceAll(rule.RuleDesc, "\n", ""))
}

// for json: a rule with the list of subnets it splits
type splitRuleSubnetJSON struct {
	VpcName      string                `json:"vpc_name"`
	Rule         vpcmodel.RuleOfFilter `json:"rule_details"`
	SplitSubnets []subnetJSON          `json:"splitted_subnets"`
}

func (finding *splitRuleSubnet) toJSON() any {
	rule := finding.rule
	splitSubnetsJSON := make([]subnetJSON, len(finding.splitSubnets))
	for i := range finding.splitSubnets {
		splitSubnetsJSON[i] = subnetJSON{Name: finding.splitSubnets[i].Name(), CIDR: finding.splitSubnets[i].CIDR()}
	}
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	res := splitRuleSubnetJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc},
		SplitSubnets: splitSubnetsJSON}
	return res
}
