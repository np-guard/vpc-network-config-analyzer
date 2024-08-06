/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const NetworkACL = "network ACL" // todo: https://github.com/np-guard/vpc-network-config-analyzer/issues/724

// a rule that is implied syntactically redundant:
// nacl rule - implied by higher priority rules in the nacl table
// sg rule - implied by other rules in the sg table
type ruleRedundant struct {
	rule         vpcmodel.RuleOfFilter
	containRules map[int]string // indexes of rules because of which this rule is redundant to their description
	vpcResource  vpcmodel.VPC
}

////////////////////////////////////////////////////////////////////////////////////////////
// functionality used by both SG and NACL lints
////////////////////////////////////////////////////////////////////////////////////////////

// Rule is syntactically redundant in SG if other rules in the table implies it
// Rule is syntactically redundant in NACL if it is shadowed by higher priority rules of the table
// A rule is shadowed in NACL if the rule will never determine the actual allow/deny status
// (of any connection in any configuration)
// A rule in a table has 3 dimensions: source, destination and connection
// SG rule is redundant if the 3-dimensions union of the other rules contains it, thus rule is implied by others
// NACL rule  is redundant if the 3-dimensions union of the higher priority (allow or deny) rules contains it
// The above 3 dimensions containment is checked as follows:
// in the below a "point" is a point in the src x dst x conn 3-dimensions
// If each point in the rule is contained in the others/higher priority rules then it is redundant
// This we check as follows:
// For each table:
//  1. partition the IPBlock to maximal atomic blocks w.r.t. the table
//  2. For each rule r:
//     2.1. Iterate over the cartesian product of r's src and dst atomic blocks
//     For each item <src_atomic, dst_atomic>
//     compute the union of the connection of the other/higher priority rules whose <src, dst> contains <src_atomic, dst_atomic>
//     If the resulting conn does not contain the connection of the rule r then the block is not redundant
//     Done? Rule is redundant
//
//nolint:gocyclo // better not split into two function
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
		tableToRules, tableToAtomicBlocks := getTableOrientedStructs(rules)
		// iterates over tables, in each table iterates over rules finds those that are redundant (shadowed/implied)
		for tableIndex, rules := range tableToRules {
			tableAtomicBlocks := tableToAtomicBlocks[tableIndex]
			for i := range rules {
				isRedundantRuleIndex := rules[i].RuleIndex
				// gathers atomic blocks within rule's src and dst
				srcBlocks := getAtomicBlocksOfSrcOrDst(tableAtomicBlocks, rules[i].SrcCidr)
				dstBlocks := getAtomicBlocksOfSrcOrDst(tableAtomicBlocks, rules[i].DstCidr)
				// iterates over cartesian product of atomic blocks within rule's src and dst; rule is redundant if all
				// items in the cartesian product are shadowed/implies
				ruleIsRedundant := true
				containRules := map[int]string{}
				for _, srcAtomicBlock := range srcBlocks {
					for _, dstAtomicBlock := range dstBlocks {
						connOfOthers := connection.None()
						// computes the connection of other/higher priority rules in this atomic point in the 3-dimension space
						for otherRuleIndex, otherRule := range tableToRules[tableIndex] {
							if isRedundantRuleIndex == otherRuleIndex {
								if filterLayerName == vpcmodel.NaclLayer {
									break // shadow only by higher priority rules
								} else { // security group
									continue // do not consider the rule checked for redundancy
								}
							}
							// otherRule contributes to the shadowing/implication?
							// namely, it contains src, dst and has a relevant connection?
							if rules[i].IsIngress == otherRule.IsIngress &&
								srcAtomicBlock.ContainedIn(otherRule.SrcCidr) &&
								dstAtomicBlock.ContainedIn(otherRule.DstCidr) &&
								!rules[i].Conn.Intersect(otherRule.Conn).IsEmpty() {
								connOfOthers = connOfOthers.Union(otherRule.Conn)
								if _, ok := containRules[otherRuleIndex]; !ok {
									containRules[otherRuleIndex] = otherRule.RuleDesc
								}
							}
						}
						// is <src, dst> shadowed/implied by other rules?
						if !rules[i].Conn.ContainedIn(connOfOthers) {
							ruleIsRedundant = false
							break
						}
					}
				}
				if ruleIsRedundant {
					res = append(res, ruleRedundant{vpcResource: config.VPC, rule: *rules[i], containRules: containRules})
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

// Generates and returns two maps from tables of layer (their indexes):
// 1. To a slice of its rules, where the location in the slice is the index of the rule
// 2. To slice of the atomic blocks of the table
func getTableOrientedStructs(rules []vpcmodel.RuleOfFilter) (tableToRules map[int][]*vpcmodel.RuleOfFilter,
	tableToAtomicBlocks map[int][]*ipblock.IPBlock,
) {
	// 1.1 Computes the number of rules in each table, to determine the size of each slice in the map tableToRules
	tableToSize := map[int]int{}
	for i := range rules {
		filterIndex := rules[i].Filter.FilterIndex
		tableToSize[filterIndex]++
	}
	tableToRules = map[int][]*vpcmodel.RuleOfFilter{}
	// 1.2 Initialize tableToRules with the above computed sizes
	for i, size := range tableToSize {
		tableToRules[i] = make([]*vpcmodel.RuleOfFilter, size)
	}
	// 1.3 Populates tableToRules
	for i := range rules {
		filterIndex := rules[i].Filter.FilterIndex
		tableToRules[filterIndex][rules[i].RuleIndex] = &rules[i]
	}
	// 2. For each table computes its atomic blocks and creates the above resulting map
	tableToAtomicBlocks = map[int][]*ipblock.IPBlock{}
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
	strResPrefix := fmt.Sprintf("In VPC %s %s %s's rule %d is redundant. ",
		finding.vpcResource.Name(), finding.rule.Filter.LayerName, rule.Filter.FilterName, rule.RuleIndex)
	if rule.Filter.LayerName == NetworkACL {
		if len(finding.containRules) == 1 {
			strResPrefix += "It is shadowed by a higher priority rule"
		} else { // >1
			strResPrefix += "It is shadowed by higher priority rules"
		}
	} else {
		if len(finding.containRules) == 1 {
			strResPrefix += "It is implied by another rule"
		} else { // >1
			strResPrefix += "It is implied by other rules"
		}
	}
	strResPrefix = strResPrefix + "\n\tRule's details: " + rule.RuleDesc
	if rule.Filter.LayerName == NetworkACL {
		strResPrefix += "\t\tShadowing rule"
	} else {
		strResPrefix += "\t\tImplying rule"
	}
	if len(finding.containRules) > 1 {
		strResPrefix += "s:\n\t\t"
	} else {
		strResPrefix += ": "
	}
	containingRulesSlice := []string{}
	for _, ruleStr := range finding.containRules {
		containingRulesSlice = append(containingRulesSlice, ruleStr)
	}
	sort.Strings(containingRulesSlice)
	return strResPrefix + strings.Join(containingRulesSlice, "\t\t")
}

// for json:
type ruleRedundantJSON struct {
	Rule         vpcmodel.RuleOfFilter `json:"vpc_name"`
	VpcName      string                `json:"rule_details"`
	ContainRules []string              // rules because of which this rule is redundant to their description
}

func (finding *ruleRedundant) toJSON() any {
	rule := finding.rule
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	containRules := make([]string, len(finding.containRules))
	for i, rule := range finding.containRules {
		containRules[i] = rule
	}
	res := ruleRedundantJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc}, ContainRules: containRules}
	return res
}
