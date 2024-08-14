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

// SG rules that are inconsistent w.r.t. subnets.
func newSGSplitSubnet(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "SGs implying different connectivity for endpoints inside a subnet",
			enable:      false,
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findSplitRulesSubnet}
}

// NACL rules that are inconsistent w.r.t. subnets.
func newNACLSplitSubnet(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "NACLs implying different connectivity for endpoints inside a subnet",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findSplitRulesSubnet}
}

////////////////////////////////////////////////////////////////////////////////////////////
// functionality used by both filterRuleSplitSubnetLintNACL and filterRuleSplitSubnetLintSG
////////////////////////////////////////////////////////////////////////////////////////////

func findSplitRulesSubnet(configs map[string]*vpcmodel.VPCConfig, filterLayerName string) (res []finding, err error) {
	for _, config := range configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		for i := range rules {
			subnetsSplitByRule := []vpcmodel.Subnet{}
			for _, subnet := range config.Subnets {
				splitSubnet := ruleSplitSubnet(subnet, [2]*ipblock.IPBlock{rules[i].SrcCidr, rules[i].DstCidr})
				if splitSubnet {
					subnetsSplitByRule = append(subnetsSplitByRule, subnet)
				}
			}
			if len(subnetsSplitByRule) > 0 {
				res = append(res, &splitRuleSubnet{rule: rules[i], splitSubnets: subnetsSplitByRule})
			}
		}
	}
	return res, nil
}

// given a subnet and IPBlocks mentioned in a rule, returns true if the rules split any of the blocks
func ruleSplitSubnet(subnet vpcmodel.Subnet, ruleIPBlocks [2]*ipblock.IPBlock) bool {
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

func (finding *splitRuleSubnet) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.splitSubnets[0].VPC()}
}

func (finding *splitRuleSubnet) string() string {
	rule := finding.rule
	subnetsStrSlice := make([]string, len(finding.splitSubnets))
	for i, subnet := range finding.splitSubnets {
		subnetsStrSlice[i] = fmt.Sprintf("%q (%s)", subnet.Name(), subnet.CIDR())
	}
	subnetStr := strings.Join(subnetsStrSlice, ", ")
	if len(subnetsStrSlice) > 1 {
		subnetStr = "subnets " + subnetStr
	} else {
		subnetStr = "subnet " + subnetStr
	}
	return fmt.Sprintf("In VPC %q, %s %q rule [%d] splits %s.\n\tRule's details: %s",
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
	for i, splitSubnet := range finding.splitSubnets {
		splitSubnetsJSON[i] = subnetJSON{Name: splitSubnet.Name(), CIDR: splitSubnet.CIDR()}
	}
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	res := splitRuleSubnetJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc},
		SplitSubnets: splitSubnetsJSON}
	return res
}
