/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"fmt"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
)

const protocolTCP = "tcp"

// SGAnalyzer captures common securityGroup properties for aws and ibm: rules and connectivityMaps
type SGAnalyzer struct {
	SgAnalyzer   SpecificSGAnalyzer
	ingressRules []*SGRule
	egressRules  []*SGRule
	// rules are the default ones; that is, no rules were specified manually
	isDefault              bool
	ingressConnectivityMap ConnectivityResultMap
	egressConnectivityMap  ConnectivityResultMap
}

// interface to be implemented by aws and ibm sg analyzer
type SpecificSGAnalyzer interface {
	GetSGRules() (ingressRules, egressRules []*SGRule, err error)
	ReferencedIPblocks() []*netset.IPBlock
	SetSGmap(sgMap map[string]*SecurityGroup)
	GetNumberOfRules() int
	GetSGRule(index int) (ruleStr string, ruleRes *SGRule, isIngress bool, err error)
	Name() *string
}

func NewSGAnalyzer(analyzer SpecificSGAnalyzer) *SGAnalyzer {
	res := &SGAnalyzer{SgAnalyzer: analyzer}
	return res
}

// GetProperty returns pointer p if it is valid, else it returns the provided default value
// used to get min/max port or icmp type
func GetProperty(p *int64, defaultP int64) int64 {
	if p == nil {
		return defaultP
	}
	return *p
}

// GetTCPUDPConns returns TCP or UDP connection
func GetTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *netset.TransportSet {
	protocol := netp.ProtocolStringUDP
	if p == protocolTCP {
		protocol = netp.ProtocolStringTCP
	}
	return netset.NewTCPorUDPTransport(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
}

// GetICMPconn returns ICMP connection
func GetICMPconn(icmpType, icmpCode *int64) *netset.TransportSet {
	typeMin := GetProperty(icmpType, int64(netp.MinICMPType))
	typeMax := GetProperty(icmpType, int64(netp.MaxICMPType))
	codeMin := GetProperty(icmpCode, int64(netp.MinICMPCode))
	codeMax := GetProperty(icmpCode, int64(netp.MaxICMPCode))
	return netset.NewICMPTransport(typeMin, typeMax, codeMin, codeMax)
}

// RuleTarget represents a securityGroup rule target, used in ibm and aws
type RuleTarget struct {
	Cidr   *netset.IPBlock
	SgName string // target specified is SG
}

func NewRuleTarget(cidr *netset.IPBlock, sgName string) *RuleTarget {
	res := &RuleTarget{Cidr: cidr, SgName: sgName}
	return res
}

type SGRule struct {
	Remote      *RuleTarget
	Connections *netset.TransportSet
	Index       int // index of original rule in *vpc1.SecurityGroup.Rules
	Local       *netset.IPBlock
}

// analyzeSGRules gets security group rules and returns it's connectivity results
func analyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	remotes := []*netset.IPBlock{}
	for i := range rules {
		if rules[i].Remote.Cidr != nil && !rules[i].Remote.Cidr.IsEmpty() {
			remotes = append(remotes, rules[i].Remote.Cidr)
		}
	}
	disjointTargets := netset.DisjointIPBlocks(remotes, []*netset.IPBlock{netset.GetCidrAll()})
	res := &ConnectivityResult{IsIngress: isIngress, AllowedConns: map[*netset.IPBlock]*netset.TransportSet{},
		AllowRules: map[*netset.IPBlock][]int{}}
	for i := range disjointTargets {
		res.AllowedConns[disjointTargets[i]] = netset.NoTransports()
		res.AllowRules[disjointTargets[i]] = []int{}
	}
	for i := range rules {
		rule := rules[i]
		remote := rule.Remote
		conn := rule.Connections
		for disjointTarget := range res.AllowedConns {
			if disjointTarget.IsSubset(remote.Cidr) {
				res.AllowedConns[disjointTarget] = res.AllowedConns[disjointTarget].Union(conn)
				res.AllowRules[disjointTarget] = append(res.AllowRules[disjointTarget], rule.Index)
			}
		}
	}

	return res
}

// analyzeSGRules gets security group rules and returns a map from local ip block intervals to it's connectivity results
func MapAndAnalyzeSGRules(rules []*SGRule, isIngress bool, currentSg *SecurityGroup) (connectivityMap ConnectivityResultMap) {
	connectivityMap = make(ConnectivityResultMap)
	locals := []*netset.IPBlock{}
	for i := range rules {
		if rules[i].Local != nil {
			locals = append(locals, rules[i].Local)
		}
	}
	disjointLocals := netset.DisjointIPBlocks(locals, []*netset.IPBlock{netset.GetCidrAll()})
	keysToConnectivityResult := map[common.SetAsKey]*ConnectivityResult{}
	unifiedMembersIPBlock := currentSg.unifiedMembersIPBlock()
	for i := range disjointLocals {
		if !disjointLocals[i].Overlap(unifiedMembersIPBlock) {
			// no need to compute connectivity for local range that has no SG members within it
			continue
		}
		relevantRules := []*SGRule{}
		for j := range rules {
			if disjointLocals[i].IsSubset(rules[j].Local) {
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

// PrepareAnalyzer used to map and analyze securityGroup rules and save the results
func (sga *SGAnalyzer) PrepareAnalyzer(sgMap map[string]*SecurityGroup, currentSg *SecurityGroup) error {
	if len(currentSg.Members) == 0 {
		return nil // avoid analysis sg which is not applied to any members
	}
	var err error
	sga.SgAnalyzer.SetSGmap(sgMap)
	if sga.ingressRules, sga.egressRules, err = sga.SgAnalyzer.GetSGRules(); err != nil {
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
	if egressRuleCidrs[0] == netset.CidrAll && egressRule.Connections.IsAll() {
		return true
	}
	return false
}

func (sga *SGAnalyzer) allowedConnectivity(target, local *netset.IPBlock, isIngress bool) *netset.TransportSet {
	analyzedConnsMap := sga.ingressOrEgressConnectivity(isIngress)
	for definedLocal, analyzedConns := range analyzedConnsMap {
		if local.IsSubset(definedLocal) {
			for definedTarget, conn := range analyzedConns.AllowedConns {
				if target.IsSubset(definedTarget) {
					return conn
				}
			}
		}
	}

	return netset.NoTransports()
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity, if the required connection exists
//  1. The required connection (src/dst) is detected, if exists.
//  2. If connection is part of the query: is the required connection contained in the existing connection?
//     if it does, then the contributing rules are detected: rules that intersect the required connection
//     otherwise, the answer to the query is "no" and nil is returned
func (sga *SGAnalyzer) rulesFilterInConnectivity(target, local *netset.IPBlock,
	connQuery *netset.TransportSet, isIngress bool) ([]int, error) {
	analyzedConnsMap := sga.ingressOrEgressConnectivity(isIngress)
	for definedLocal, analyzedConns := range analyzedConnsMap {
		if local.IsSubset(definedLocal) {
			for definedTarget, rules := range analyzedConns.AllowRules {
				if target.IsSubset(definedTarget) {
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
func (sga *SGAnalyzer) getRulesRelevantConn(rules []int, conn *netset.TransportSet) ([]int, error) {
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

// GetIPBlockResult gets an cidr, address or name of the remote/local rule object, and returns it's IPBlock
func GetIPBlockResult(cidr, address, name *string,
	sgMap map[string]*SecurityGroup) (*netset.IPBlock, string, error) {
	var ipBlock *netset.IPBlock
	var cidrRes string
	var err error
	switch {
	case cidr != nil:
		ipBlock, err = netset.IPBlockFromCidr(*cidr)
		if err != nil {
			return nil, "", err
		}
		cidrRes = ipBlock.ToCidrList()[0]
	case address != nil:
		ipBlock, err = netset.IPBlockFromIPAddress(*address)
		if err != nil {
			return nil, "", err
		}
		cidrRes = ipBlock.ToCidrList()[0]
	case name != nil:
		ipBlock = netset.NewIPBlock()
		if sg, ok := sgMap[*name]; ok {
			for member := range sg.Members {
				memberIPBlock, err := netset.IPBlockFromIPAddress(member)
				if err != nil {
					return nil, "", err
				}
				ipBlock = ipBlock.Union(memberIPBlock)
			}
			cidrRes = strings.Join(ipBlock.ToCidrList(), ",")
		}
	default:
		return nil, "", fmt.Errorf("sg error: getCidrResult - SecurityGroupRule is empty")
	}
	if ipBlock == nil {
		return nil, "", fmt.Errorf("getIPBlockResult err: unexpected nil ipBlock returned")
	}
	if ipBlock.IsEmpty() {
		logging.Debugf("SG rule references an empty IPBlock, rule will be ignored")
	}
	return ipBlock, cidrRes, nil
}

// GetSGRules returns ingress and egress rule objects
func GetSGRules(sga SpecificSGAnalyzer) (ingressRules, egressRules []*SGRule, err error) {
	ingressRules = []*SGRule{}
	egressRules = []*SGRule{}
	for index := 0; index < sga.GetNumberOfRules(); index++ {
		_, ruleObj, isIngress, err := sga.GetSGRule(index)
		if err != nil {
			return nil, nil, err
		}
		if ruleObj == nil {
			continue
		}
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules, nil
}
