/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const splitRuleSubnetName = "rules-splitting-subnets"

// filterRuleSplitSubnet: rules of filters that are inconsistent w.r.t. subnets.
type filterRuleSplitSubnet struct {
	basicLinter
	findings []*splitRuleSubnet
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

func (lint *filterRuleSplitSubnet) check() (bool, error) {
	lintOK := true
	findingRes := []*splitRuleSubnet{}
	for _, config := range lint.configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		for _, layer := range vpcmodel.FilterLayers {
			filterLayer := config.GetFilterTrafficResourceOfKind(layer)
			rules, err := filterLayer.GetRules()
			if err != nil {
				return false, err
			}
			for _, rule := range rules {
				subnetsSplitByRule := []vpcmodel.Subnet{}
				for _, subnet := range config.Subnets {
					splitSubnet, err := ruleSplitSubnet(subnet, rule.IPBlocks)
					if err != nil {
						return false, err
					}
					if splitSubnet {
						lintOK = false
						subnetsSplitByRule = append(subnetsSplitByRule, subnet)
					}
				}
				if len(subnetsSplitByRule) > 0 {
					findingRes = append(findingRes, &splitRuleSubnet{vpcName: config.VPC.Name(), rule: rule,
						splitSubnets: subnetsSplitByRule})
				}
			}
		}
	}
	lint.findings = findingRes
	return lintOK, nil
}

func (lint *filterRuleSplitSubnet) string() string {
	findingsRes := make([]string, len(lint.findings))
	for i, thisFinding := range lint.findings {
		findingsRes[i] = thisFinding.string()
	}
	sort.Strings(findingsRes)
	header := fmt.Sprintf("%q %s\n", lint.lintDescription(), issues) +
		strings.Repeat("-", len(lint.lintDescription())+len(issues)+3) + "\n"
	return header + strings.Join(findingsRes, "")
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

func (lint *filterRuleSplitSubnet) getFindings() []finding {
	resFinding := make([]finding, len(lint.findings))
	for i, issue := range lint.findings {
		resFinding[i] = issue
	}
	return resFinding
}

// ToJSON todo impl
func (lint *filterRuleSplitSubnet) toJSON() []any {
	return nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for splitRuleSubnet
//////////////////////////////////////////////////////////

func (finding *splitRuleSubnet) vpc() string {
	return finding.vpcName
}

func (finding *splitRuleSubnet) string() string {
	rule := finding.rule
	thisLayerName := "Network acl"
	if finding.rule.LayerName == vpcmodel.SecurityGroupLayer {
		thisLayerName = "Security group"
	}
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
		finding.vpc(), thisLayerName, rule.FilterName, rule.RuleIndx, subnetStr, rule.RuleDesc)
}

func (finding *splitRuleSubnet) toJSON() any {
	return nil // todo impl
}
