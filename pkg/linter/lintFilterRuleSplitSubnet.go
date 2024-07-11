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

const splitRuleSubnetName = "rules-splitting-subnets"

// filterRuleSplitSubnet: rules of filters that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnet struct {
	basicLinter
}

// a rule with the list of subnets it splits
type splitRuleSubnet struct {
	vpcName      string
	rule         vpcmodel.RuleOfFilter
	splitSubnets []vpcmodel.Subnet
}

// /////////////////////////////////////////////////////////
// lint interface implementation for filterRuleSplitSubnet
// ////////////////////////////////////////////////////////
func (lint *filterRuleSplitSubnet) lintName() string {
	return splitRuleSubnetName
}

func (lint *filterRuleSplitSubnet) lintDescription() string {
	return "Firewall rules implying different connectivity for different endpoints within a subnet"
}

func (lint *filterRuleSplitSubnet) check() error {
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		for _, layer := range vpcmodel.FilterLayers {
			filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			rules, err := filterLayer.GetRules()
			if err != nil {
				return err
			}
			for _, rule := range rules {
				subnetsSplitByRule := []vpcmodel.Subnet{}
				for _, subnet := range config.Subnets {
					splitSubnet := ruleSplitSubnet(subnet, rule.IPBlocks)
					if splitSubnet {
						subnetsSplitByRule = append(subnetsSplitByRule, subnet)
					}
				}
				if len(subnetsSplitByRule) > 0 {
					lint.addFinding(&splitRuleSubnet{vpcName: config.VPC.Name(), rule: rule,
						splitSubnets: subnetsSplitByRule})
				}
			}
		}
	}
	return nil
}

// given a subnet and IPBlocks mentioned in a rule, returns the list
func ruleSplitSubnet(subnet vpcmodel.Subnet, ruleIPBlocks []*ipblock.IPBlock) bool {
	subnetCidrIPBlock := subnet.AddressRange()
	for _, ruleIPBlock := range ruleIPBlocks {
		if ruleIPBlock.Overlap(subnetCidrIPBlock) && !subnetCidrIPBlock.ContainedIn(ruleIPBlock) {
			return true
		}
	}
	return false
}

///////////////////////////////////////////////////////////
// finding interface implementation for splitRuleSubnet
//////////////////////////////////////////////////////////

func (finding *splitRuleSubnet) vpc() string {
	return finding.vpcName
}

func (finding *splitRuleSubnet) string() string {
	rule := finding.rule
	subnetsStrSlice := make([]string, len(finding.splitSubnets))
	for i, subnet := range finding.splitSubnets {
		subnetsStrSlice[i] = fmt.Sprintf("%s (%s)", subnet.Name(), subnet.CIDR())
	}
	subnetStr := strings.Join(subnetsStrSlice, ", ")
	if len(subnetsStrSlice) > 1 {
		subnetStr = "subnets " + subnetStr
	} else {
		subnetStr = "subnet " + subnetStr
	}
	return fmt.Sprintf("In VPC %s, %s %s rule's indexed %d splits %s. Splitting rule details: %s",
		finding.vpc(), finding.rule.LayerName, rule.FilterName, rule.RuleIndex, subnetStr, rule.RuleDesc)
}

// for json: a rule with the list of subnets it splits
type splitRuleSubnetJSON struct {
	VpcName      string                `json:"vpc_name"`
	Rule         vpcmodel.RuleOfFilter `json:"rule_details"`
	SplitSubnets []subnetJSON          `json:"splitted_subnets"`
}

type subnetJSON struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

func (finding *splitRuleSubnet) toJSON() any {
	rule := finding.rule
	splitSubnetsJSON := make([]subnetJSON, len(finding.splitSubnets))
	for i, splitSubnet := range finding.splitSubnets {
		splitSubnetsJSON[i] = subnetJSON{Name: splitSubnet.Name(), CIDR: splitSubnet.CIDR()}
	}
	res := splitRuleSubnetJSON{VpcName: finding.vpcName, Rule: vpcmodel.RuleOfFilter{LayerName: rule.LayerName,
		FilterName: rule.FilterName, RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc},
		SplitSubnets: splitSubnetsJSON}
	return res
}
