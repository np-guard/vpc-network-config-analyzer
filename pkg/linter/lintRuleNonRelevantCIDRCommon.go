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
// has a part to withing the vpc and is not all range
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
		vpcAdrressRange := config.VPC.AddressRange()
		filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		var isDisjoint, nonDisjointNonContained bool
		for _, rule := range rules {
			if rule.IsIngress {
				isDisjoint, nonDisjointNonContained = blockNonRelevantToVPC(vpcAdrressRange, rule.DstCidr)
			} else {
				isDisjoint, nonDisjointNonContained = blockNonRelevantToVPC(vpcAdrressRange, rule.SrcCidr)
			}
			if isDisjoint || nonDisjointNonContained {
				res = append(res, ruleNonRelevantCIDR{rule: rule, vpcResource: config.VPC, disjoint: isDisjoint})
			}
		}
	}
	return res, nil
}

// returns two bools: whether block is disjoint to vpcAdrressRange
// else, whether it is not contained in it
func blockNonRelevantToVPC(vpcAdrressRange, block *ipblock.IPBlock) (isDisjoint, nonDisjointNonContained bool) {
	if block.Equal(ipblock.GetCidrAll()) {
		return false, false // non-relevant if the block is the entire range
	}
	if !block.Overlap(vpcAdrressRange) {
		return true, false
	}
	if !block.ContainedIn(vpcAdrressRange) {
		return false, true
	}
	return false, false
}

///////////////////////////////////////////////////////////
// finding interface implementation for ruleNonRelevantCIDR
//////////////////////////////////////////////////////////

func (finding *ruleNonRelevantCIDR) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.vpcResource}
}

func (finding *ruleNonRelevantCIDR) string() string {
	rule := finding.rule
	var strPrefix, issueStr, strSuffix string
	if rule.IsIngress {
		strPrefix = fmt.Sprintf("Ingress rule with destiniation %s", finding.rule.DstCidr.String())
	} else {
		strPrefix = fmt.Sprintf("Egress rule with source %s", finding.rule.SrcCidr.String())
	}
	if finding.disjoint {
		issueStr = " is disjoint to "
	} else {
		issueStr = " has disjoint parts with "
	}
	strSuffix = fmt.Sprintf(" the VPC %s Address Range %s\n\tRule's details: %s", finding.vpcResource.Name(),
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
