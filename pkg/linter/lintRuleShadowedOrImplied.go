/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package linter

import (
	"fmt"
	"slices"
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
	containRules map[int]*vpcmodel.RuleOfFilter // indexes of rules because of which this rule is redundant to their description
	vpcResource  vpcmodel.VPC
}

// NACL rules that are shadowed by higher priority rules
func newNACLRuleShadowed(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "rules of network ACLs that are shadowed by higher priority rules",
			enable:      true,
		},
		layer:          vpcmodel.NaclLayer,
		checkForFilter: findRuleSyntacticRedundant}
}

// SG rules that are implied by other rules
func newSGRuleImplied(name string, configs map[string]*vpcmodel.VPCConfig,
	_ map[string]*vpcmodel.VPCConnectivity) linter {
	return &filterLinter{
		basicLinter: basicLinter{
			configs:     configs,
			name:        name,
			description: "security group rules that are implied by other rules",
			enable:      true,
		},
		layer:          vpcmodel.SecurityGroupLayer,
		checkForFilter: findRuleSyntacticRedundant}
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
	filterLayerName string) (res []finding, err error) {
	for _, config := range configs {
		if config.IsMultipleVPCsConfig {
			continue // no use in executing lint on dummy vpcs
		}
		tableToRules, tableToAtomicBlocks, err := getTablesRulesAndAtomicBlocks(config, filterLayerName)
		if err != nil {
			return nil, err
		}
		// iterates over tables, in each table iterates over rules and finds those that are redundant (shadowed/implied)
		for tableIndex, tableRules := range tableToRules {
			tableAtomicBlocks := tableToAtomicBlocks[tableIndex]
			for redundantRuleIndex, redundantRule := range tableRules {
				// nacl - redundant if shadowed by over higher priority rules; sg - redundant if implied by "other" rule
				// in the former case iterates only over relevant slice; in the latter skip the "myself" rule
				var rulesToIterate []*vpcmodel.RuleOfFilter
				if filterLayerName == vpcmodel.NaclLayer {
					rulesToIterate = tableRules[:redundantRuleIndex]
				} else { // SG
					rulesToIterate = append(slices.Clone(tableRules[:redundantRuleIndex]), tableRules[redundantRuleIndex+1:]...)
				}
				// gathers atomic blocks within rule's src and dst
				srcBlocks := getAtomicBlocks(tableAtomicBlocks, redundantRule.SrcCidr)
				dstBlocks := getAtomicBlocks(tableAtomicBlocks, redundantRule.DstCidr)
				// iterates over cartesian product of atomic blocks within rule's src and dst; rule is redundant if all
				// items in the cartesian product are shadowed/implies
				ruleIsRedundant := true
				containRules := map[int]*vpcmodel.RuleOfFilter{}
				for _, srcAtomicBlock := range srcBlocks {
					for _, dstAtomicBlock := range dstBlocks {
						connOfOthers := connection.None()
						// computes the connection of other/higher priority rules in this atomic point in the 3-dimension space
						for _, otherRule := range rulesToIterate {
							// otherRule contributes to the shadowing/implication?
							// namely, it contains src, dst and has a relevant connection?
							if redundantRule.IsIngress == otherRule.IsIngress &&
								srcAtomicBlock.ContainedIn(otherRule.SrcCidr) &&
								dstAtomicBlock.ContainedIn(otherRule.DstCidr) &&
								!redundantRule.Conn.Intersect(otherRule.Conn).IsEmpty() {
								connOfOthers = connOfOthers.Union(otherRule.Conn)
								if _, ok := containRules[otherRule.RuleIndex]; !ok {
									containRules[otherRule.RuleIndex] = otherRule
								}
							}
						}
						// is <src, dst> shadowed/implied by other rules?
						if !redundantRule.Conn.ContainedIn(connOfOthers) {
							ruleIsRedundant = false
							break
						}
					}
				}
				if ruleIsRedundant {
					res = append(res, &ruleRedundant{vpcResource: config.VPC, rule: *redundantRule, containRules: containRules})
				}
			}
		}
	}
	return res, nil
}

func getAtomicBlocks(atomicBlocks []*ipblock.IPBlock, srcOrdst *ipblock.IPBlock) []*ipblock.IPBlock {
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
func getTablesRulesAndAtomicBlocks(config *vpcmodel.VPCConfig, filterLayerName string) (tableToRules map[int][]*vpcmodel.RuleOfFilter,
	tableToAtomicBlocks map[int][]*ipblock.IPBlock, err error) {
	filterLayer := config.GetFilterTrafficResourceOfKind(filterLayerName)
	rules, err := filterLayer.GetRules()
	if err != nil {
		return nil, nil, err
	}
	tableToRules = map[int][]*vpcmodel.RuleOfFilter{}
	tableToAtomicBlocks = map[int][]*ipblock.IPBlock{}
	for i := range rules {
		filterIndex := rules[i].Filter.FilterIndex
		tableToRules[filterIndex] = append(tableToRules[filterIndex], &rules[i])
		tableToAtomicBlocks[filterIndex] = append(tableToAtomicBlocks[filterIndex], rules[i].SrcCidr)
		tableToAtomicBlocks[filterIndex] = append(tableToAtomicBlocks[filterIndex], rules[i].DstCidr)
	}
	for tableIndex := range tableToRules {
		slices.SortFunc(tableToRules[tableIndex], func(r1, r2 *vpcmodel.RuleOfFilter) int {
			return r1.RuleIndex - r2.RuleIndex
		})
		tableToAtomicBlocks[tableIndex] = ipblock.DisjointIPBlocks(tableToAtomicBlocks[tableIndex], nil)
	}
	return tableToRules, tableToAtomicBlocks, err
}

/////////////////////////////////////////////////////////////
//// finding interface implementation for ruleRedundant
////////////////////////////////////////////////////////////

func (finding *ruleRedundant) vpc() []vpcmodel.VPCResourceIntf {
	return []vpcmodel.VPCResourceIntf{finding.vpcResource}
}

func (finding *ruleRedundant) string() string {
	rule := finding.rule
	strResPrefix := fmt.Sprintf("In VPC %q, %s %q rule [%d] is ",
		finding.vpcResource.Name(), finding.rule.Filter.LayerName, rule.Filter.FilterName, rule.RuleIndex)
	if rule.Filter.LayerName == NetworkACL {
		if len(finding.containRules) == 1 {
			strResPrefix += "shadowed by a higher priority rule"
		} else { // >1
			strResPrefix += "shadowed by higher priority rules"
		}
	} else {
		if len(finding.containRules) == 1 {
			strResPrefix += "implied by another rule"
		} else { // >1
			strResPrefix += "implied by other rules"
		}
	}
	strResPrefix = strResPrefix + "\n\tRule details: " + rule.RuleDesc
	if rule.Filter.LayerName == NetworkACL {
		strResPrefix += "\t\tShadowing rule"
	} else {
		strResPrefix += "\t\tImplying rule"
	}
	if len(finding.containRules) > 1 {
		strResPrefix += "s:\n\t\t\t"
	} else {
		strResPrefix += ": "
	}
	containingRulesSlice := []string{}
	for _, rule := range finding.containRules {
		containingRulesSlice = append(containingRulesSlice, rule.RuleDesc)
	}
	sort.Strings(containingRulesSlice)
	return strResPrefix + strings.Join(containingRulesSlice, "\t\t\t")
}

// for json:
type ruleRedundantJSON struct {
	Rule         vpcmodel.RuleOfFilter   `json:"vpc_name"`
	VpcName      string                  `json:"rule_details"`
	ContainRules []vpcmodel.RuleOfFilter `json:"containing_rules"` // rules because of which this rule is redundant to their description
}

func (finding *ruleRedundant) toJSON() any {
	rule := finding.rule
	table := vpcmodel.Filter{LayerName: rule.Filter.LayerName,
		FilterName: rule.Filter.FilterName}
	containRules := make([]vpcmodel.RuleOfFilter, len(finding.containRules))
	i := 0
	for _, rule := range finding.containRules {
		containRules[i] = *rule
		i++
	}
	res := ruleRedundantJSON{VpcName: finding.vpc()[0].Name(), Rule: vpcmodel.RuleOfFilter{Filter: table,
		RuleIndex: rule.RuleIndex, RuleDesc: rule.RuleDesc}, ContainRules: containRules}
	return res
}
