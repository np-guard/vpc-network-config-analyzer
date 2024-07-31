/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const NetworkACL = "network ACL" // todo: https://github.com/np-guard/vpc-network-config-analyzer/issues/724

// a rule that is implied syntactically redundant:
// nacl rule - implied by higher priority rules in the nacl table
// sg rule - implied by other rules in the sg table
type ruleRedundant struct {
	rule        vpcmodel.RuleOfFilter
	vpcResource vpcmodel.VPC
}

////////////////////////////////////////////////////////////////////////////////////////////
// functionality used by both SG and NACL lints
////////////////////////////////////////////////////////////////////////////////////////////

// Rule is syntactically redundant in SG if other rules in the table implies it
// and if other, higher priority rules, overrules it in NACL
// A rule in a table has 3 dimensions: source, destination and connection
// SG rule is redundant if the 3-dimensions union of the other rules contain it
// NACL rule  is redundant if the 3-dimensions union of the higher priority (allow or deny) rules contain it
// The above 3 dimensions containment is checked as follows:
// in the below a "point" is a point in the src, dst, conn 3-dimensions
// If each point in the rule is contained in the others/higher priority rules then it is redundant
// This we check as follows:
// For each table:
// 1. partition the IPBlock to maximal atomic blocks w.r.t. the table
// 2. For each rule:
//    2.1. For each couple of atomic block in the src and atomic block in the dest, compute the union of the connection
//         of the other/higher priority blocks that refers to it
//         If the resulting conn does not contain the connection of the rule then the block is not redundant
//         otherwise, continue to the next couple
//   Done? Rule is redundant

func findRuleSyntacticRedundant(configs map[string]*vpcmodel.VPCConfig,
	filterLayerName string) (res []ruleRedundant, err error) {
	for _, config := range configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
		rules, err := filterLayer.GetRules()
		if err != nil {
			return nil, err
		}
		tableToRules, tableToAtomicBlocks := getTableToAtomicBlocks(rules)
		for isRedundantRule := range rules {
			tableIndex := rules[isRedundantRule].Filter.FilterIndex
			tableAtomicBlocks := tableToAtomicBlocks[tableIndex]
			// gathers atomic blocks within rule's src and dst
			srcBlocks := getAtomicBlocksOfSrcOrDst(tableAtomicBlocks, rules[isRedundantRule].SrcCidr)
			dstBlocks := getAtomicBlocksOfSrcOrDst(tableAtomicBlocks, rules[isRedundantRule].DstCidr)
			// iterates over cartesian product of atomic blocks within rule's src and dst
			for _, srcAtomicBlock := range srcBlocks {
				for _, dstAtomicBlock := range dstBlocks {
					// computes the connection of other/higher priority rules in this atomic point in the 3-dimension space
					connOfOthers := connection.None()
					for otherRule := range tableToRules[tableIndex] {
						if rules[isRedundantRule].RuleIndex == tableToRules[tableIndex][otherRule].RuleIndex ||
							(filterLayerName == vpcmodel.NaclLayer &&
								rules[isRedundantRule].RuleIndex <= tableToRules[tableIndex][otherRule].RuleIndex) {
							continue
						}
						if srcAtomicBlock.ContainedIn(tableToRules[tableIndex][otherRule].SrcCidr) &&
							dstAtomicBlock.ContainedIn(tableToRules[tableIndex][otherRule].DstCidr) {
							connOfOthers = connOfOthers.Union(tableToRules[tableIndex][otherRule].Conn)
						}
					}
					// is rule redundant?
					if rules[isRedundantRule].Conn.ContainedIn(connOfOthers) {
						res = append(res, ruleRedundant{vpcResource: config.VPC, rule: rules[isRedundantRule]})
					}
				}
			}
		}

	}
	return res, nil
}

func getAtomicBlocksOfSrcOrDst(atomicBlocks []*ipblock.IPBlock, srcOrdst *ipblock.IPBlock) []*ipblock.IPBlock {
	res := []*ipblock.IPBlock{}
	for _, block := range atomicBlocks {
		if block.ContainedIn(srcOrdst) {
			res = append(res, block)
		}
	}
	return res
}

// Creates a map from tables of layer (their indexes) to slice of the atomic blocks of the table
// return also a map from a table indexes to its rules
func getTableToAtomicBlocks(rules []vpcmodel.RuleOfFilter) (tableToRules map[int][]vpcmodel.RuleOfFilter,
	tableToAtomicBlocks map[int][]*ipblock.IPBlock,
) {
	// 1. Creates a map from each table index to its rules
	for i := range rules {
		if _, ok := tableToRules[rules[i].Filter.FilterIndex]; !ok {
			tableToRules[rules[i].Filter.FilterIndex] = []vpcmodel.RuleOfFilter{}
		}
		tableToRules[rules[i].Filter.FilterIndex] = append(tableToRules[rules[i].Filter.FilterIndex], rules[i])
	}
	// 2. For each table computes its atomic blocks and creates the above resulting map
	for tableIndex := range tableToRules {
		for i := range tableToRules[tableIndex] {
			thisRuleBlocks := ipblock.DisjointIPBlocks([]*ipblock.IPBlock{tableToRules[tableIndex][i].SrcCidr},
				[]*ipblock.IPBlock{tableToRules[tableIndex][i].DstCidr})
			if tableBlocks, ok := tableToAtomicBlocks[tableIndex]; !ok {
				tableToAtomicBlocks[tableIndex] = thisRuleBlocks
			} else {
				tableToAtomicBlocks[tableIndex] = ipblock.DisjointIPBlocks(tableBlocks, thisRuleBlocks)
			}
		}
	}
	return tableToRules, tableToAtomicBlocks
}

/////////////////////////////////////////////////////////////
//// finding interface implementation for ruleRedundant
////////////////////////////////////////////////////////////

func (finding *ruleRedundant) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.vpcResource}
}

func (finding *ruleRedundant) string() string {
	rule := finding.rule
	strRes := fmt.Sprintf("In VPC %s %s %s's is redundant. ",
		finding.vpcResource.Name(), finding.rule.Filter.LayerName, rule.Filter.FilterName)
	if rule.Filter.LayerName == NetworkACL {
		strRes += fmt.Sprintf("It is overruled by by higher priority rules")
	} else {
		strRes += fmt.Sprintf("It is implied by other rules in the table")
	}
	return strRes + "\n\tRule's details: " + rule.RuleDesc
}

// for json:
type ruleRedundantJSON struct {
	Rule    vpcmodel.RuleOfFilter `json:"vpc_name"`
	VpcName string                `json:"rule_details"`
}

func (finding *ruleRedundant) toJSON() any {
	rule := finding.rule
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	res := ruleRedundantJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc}}
	return res
}
