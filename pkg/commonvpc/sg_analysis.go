/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"slices"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type SGAnalyzer struct {
	SgAnalyzer   SpecificAnalyzer
	ingressRules []*SGRule
	egressRules  []*SGRule
	// rules are the default ones; that is, no rules were specified manually
	isDefault              bool
	ingressConnectivityMap ConnectivityResultMap
	egressConnectivityMap  ConnectivityResultMap
}
type SpecificAnalyzer interface {
	GetSGrules() (ingressRules, egressRules []*SGRule, err error)
	StringRules(rules []int) string
	ReferencedIPblocks() []*ipblock.IPBlock
	SetSGmap(sgMap map[string]*SecurityGroup)
	GetNumberOfRules() int
	GetSGRule(index int) (ruleStr string, ruleRes *SGRule, isIngress bool, err error)
}

func NewSGAnalyzer(analyzer SpecificAnalyzer) *SGAnalyzer {
	res := &SGAnalyzer{SgAnalyzer: analyzer}
	return res
}

func getEmptyConnSet() *connection.Set {
	return connection.None()
}

type RuleTarget struct {
	Cidr   *ipblock.IPBlock
	SgName string // target specified is SG
}

func NewRuleTarget(cidr *ipblock.IPBlock, sgName string) *RuleTarget {
	res := &RuleTarget{Cidr: cidr, SgName: sgName}
	return res
}

type SGRule struct {
	Remote      *RuleTarget
	Connections *connection.Set
	Index       int // index of original rule in *vpc1.SecurityGroup.Rules
	Local       *ipblock.IPBlock
}

func analyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	remotes := []*ipblock.IPBlock{}
	for i := range rules {
		if rules[i].Remote.Cidr != nil {
			remotes = append(remotes, rules[i].Remote.Cidr)
		}
	}
	disjointTargets := ipblock.DisjointIPBlocks(remotes, []*ipblock.IPBlock{ipblock.GetCidrAll()})
	res := &ConnectivityResult{IsIngress: isIngress, AllowedConns: map[*ipblock.IPBlock]*connection.Set{},
		AllowRules: map[*ipblock.IPBlock][]int{}}
	for i := range disjointTargets {
		res.AllowedConns[disjointTargets[i]] = getEmptyConnSet()
		res.AllowRules[disjointTargets[i]] = []int{}
	}
	for i := range rules {
		rule := rules[i]
		remote := rule.Remote
		conn := rule.Connections
		for disjointTarget := range res.AllowedConns {
			if disjointTarget.ContainedIn(remote.Cidr) {
				res.AllowedConns[disjointTarget] = res.AllowedConns[disjointTarget].Union(conn)
				res.AllowRules[disjointTarget] = append(res.AllowRules[disjointTarget], rule.Index)
			}
		}
	}

	return res
}

func MapAndAnalyzeSGRules(rules []*SGRule, isIngress bool, currentSg *SecurityGroup) (connectivityMap ConnectivityResultMap) {
	connectivityMap = make(ConnectivityResultMap)
	locals := []*ipblock.IPBlock{}
	for i := range rules {
		if rules[i].Local != nil {
			locals = append(locals, rules[i].Local)
		}
	}
	disjointLocals := ipblock.DisjointIPBlocks(locals, []*ipblock.IPBlock{ipblock.GetCidrAll()})
	keysToConnectivityResult := map[common.SetAsKey]*ConnectivityResult{}
	unifiedMembersIPBlock := currentSg.unifiedMembersIPBlock()
	for i := range disjointLocals {
		if !disjointLocals[i].Overlap(unifiedMembersIPBlock) {
			// no need to compute connectivity for local range that has no SG members within it
			continue
		}
		relevantRules := []*SGRule{}
		for j := range rules {
			if disjointLocals[i].ContainedIn(rules[j].Local) {
				relevantRules = append(relevantRules, rules[j])
			}
		}
		connectivityMap[disjointLocals[i]] = analyzeSGRules(relevantRules, isIngress)
		// check if we already called AnalyzeSGRules with the same relevantRules
		rulesKeys := common.FromList(relevantRules)
		key := rulesKeys.AsKey()
		if _, ok := keysToConnectivityResult[key]; !ok {
			connectivityMap[disjointLocals[i]] = analyzeSGRules(relevantRules, isIngress)
			keysToConnectivityResult[key] = connectivityMap[disjointLocals[i]]
		} else {
			connectivityMap[disjointLocals[i]] = keysToConnectivityResult[key]
		}
	}
	return connectivityMap
}

func (sga *SGAnalyzer) PrepareAnalyzer(sgMap map[string]*SecurityGroup, currentSg *SecurityGroup) error {
	if len(currentSg.Members) == 0 {
		return nil // avoid analysis sg which is not applied to any members
	}
	var err error
	sga.SgAnalyzer.SetSGmap(sgMap)
	if sga.ingressRules, sga.egressRules, err = sga.SgAnalyzer.GetSGrules(); err != nil {
		return err
	}
	sga.ingressConnectivityMap = MapAndAnalyzeSGRules(sga.ingressRules, true, currentSg)
	sga.egressConnectivityMap = MapAndAnalyzeSGRules(sga.egressRules, false, currentSg)
	sga.isDefault = sga.areSGRulesDefault()
	return nil
}

// areSGRulesDefault are the rules equal to the default rules,
// defined as "deny all inbound traffic and permit all outbound traffic"
// namely, no inbound rules and a single outbound rule with remote 0.0.0.0/0
func (sga *SGAnalyzer) areSGRulesDefault() bool {
	if len(sga.ingressRules) > 0 || len(sga.egressRules) != 1 {
		return false
	}
	egressRule := sga.egressRules[0]
	egressRuleCidrs := egressRule.Remote.Cidr.ToCidrList()
	if len(egressRuleCidrs) != 1 {
		return false
	}
	if egressRuleCidrs[0] == ipblock.CidrAll && egressRule.Connections.IsAll() {
		return true
	}
	return false
}

func (sga *SGAnalyzer) allowedConnectivity(target, local *ipblock.IPBlock, isIngress bool) *connection.Set {
	analyzedConnsMap := sga.ingressOrEgressConnectivity(isIngress)
	for definedLocal, analyzedConns := range analyzedConnsMap {
		if local.ContainedIn(definedLocal) {
			for definedTarget, conn := range analyzedConns.AllowedConns {
				if target.ContainedIn(definedTarget) {
					return conn
				}
			}
		}
	}

	return connection.None()
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity, if the required connection exists
//  1. The required connection (src/dst) is detected, if exists.
//  2. If connection is part of the query: is the required connection contained in the existing connection?
//     if it does, then the contributing rules are detected: rules that intersect the required connection
//     otherwise, the answer to the query is "no" and nil is returned
func (sga *SGAnalyzer) rulesFilterInConnectivity(target, local *ipblock.IPBlock, connQuery *connection.Set, isIngress bool) ([]int, error) {
	analyzedConnsMap := sga.ingressOrEgressConnectivity(isIngress)
	for definedLocal, analyzedConns := range analyzedConnsMap {
		if local.ContainedIn(definedLocal) {
			for definedTarget, rules := range analyzedConns.AllowRules {
				if target.ContainedIn(definedTarget) {
					if connQuery == nil {
						return rules, nil // connection not part of query - all rules are relevant
					}
					// connection is part of the query
					// the required connection - conn - should intersect with the existing connection
					// Namely, connection for the required protocol exists (one can query a single protocol)
					// on a nonempty set of the subnets
					intersectConn := connQuery.Intersect(analyzedConns.AllowedConns[definedTarget])
					if intersectConn.IsEmpty() {
						return nil, nil
					}
					return sga.getRulesRelevantConn(rules, connQuery)
				}
			}
		}
	}
	return nil, nil
}

// given a list of rules and a connection, return the sublist of rules that contributes to the connection
func (sga *SGAnalyzer) getRulesRelevantConn(rules []int, conn *connection.Set) ([]int, error) {
	relevantRules := []int{}
	for _, rule := range append(sga.ingressRules, sga.egressRules...) {
		if slices.Contains(rules, rule.Index) && !conn.Intersect(rule.Connections).IsEmpty() {
			relevantRules = append(relevantRules, rule.Index)
		}
	}
	return relevantRules, nil
}

func (sga *SGAnalyzer) ingressOrEgressConnectivity(isIngress bool) ConnectivityResultMap {
	if isIngress {
		return sga.ingressConnectivityMap
	}
	return sga.egressConnectivityMap
}
