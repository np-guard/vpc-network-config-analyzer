/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// a rule in which the src/dst (depending on if ingress or egress) referring to the vpc is disjoint to it or
// has a part to within the vpc and is not all range
type ruleNonRelevantCIDR struct {
	rule        vpcmodel.RuleOfFilter
	vpcResource vpcmodel.VPC
	disjoint    bool // is the relevant src/dst block disjoint to the VPC address range;
}

////////////////////////////////////////////////////////////////////////////////////////////
// functionality used by both SG and NACL lints
////////////////////////////////////////////////////////////////////////////////////////////

func findRuleNonRelevantCIDR(configs map[string]*vpcmodel.VPCConfig, filterLayerName string) (res []ruleNonRelevantCIDR, err error) {
	for _, config := range configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		vpcAddressRange := config.VPC.AddressRange()
		filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		// for ingress dst addresses ips within the VPC, for egress src
		for _, rule := range rules {
			relevantBlock := rule.SrcCidr
			if rule.IsIngress {
				relevantBlock = rule.DstCidr
			}
			if !relevantBlock.Equal(ipblock.GetCidrAll()) { // 0.0.0.0/0 common practice in rules
				if !relevantBlock.ContainedIn(vpcAddressRange) {
					res = append(res, ruleNonRelevantCIDR{rule: rule, vpcResource: config.VPC,
						disjoint: !relevantBlock.Overlap(vpcAddressRange)})
				}
			}
		}
	}
	return res, nil
}

///////////////////////////////////////////////////////////
// finding interface implementation for ruleNonRelevantCIDR
//////////////////////////////////////////////////////////

func (finding *ruleNonRelevantCIDR) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.vpcResource}
}

func (finding *ruleNonRelevantCIDR) string() string {
	rule := finding.rule
	strPrefix := fmt.Sprintf("In VPC %s %s %s's ", finding.vpcResource.Name(), finding.rule.Filter.LayerName,
		rule.Filter.FilterName)
	if rule.IsIngress {
		strPrefix += fmt.Sprintf("ingress rule indexed %d with destination %s", finding.rule.RuleIndex, finding.rule.DstCidr.String())
	} else {
		strPrefix += fmt.Sprintf("egress rule indexed %d with source %s", finding.rule.RuleIndex, finding.rule.SrcCidr.String())
	}
	var issueStr, strSuffix string
	if finding.disjoint {
		issueStr = " is disjoint to "
	} else {
		issueStr = " has disjoint parts with "
	}
	strSuffix = fmt.Sprintf("the VPC's Address Range %s\n\tRule's details: %s",
		finding.vpcResource.AddressRange().String(), rule.RuleDesc)
	return strPrefix + issueStr + strSuffix
}

// for json:
type rulesNonRelevantCIDRJSON struct {
	Rule            vpcmodel.RuleOfFilter `json:"vpc_name"`
	VpcName         string                `json:"rule_details"`
	VpcAddressRange string                `json:"vpc_address_range"`
}

func (finding *ruleNonRelevantCIDR) toJSON() any {
	rule := finding.rule
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	res := rulesNonRelevantCIDRJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc},
		VpcAddressRange: finding.vpcResource.AddressRange().String()}
	return res
}
