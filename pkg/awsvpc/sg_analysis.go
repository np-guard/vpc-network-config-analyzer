/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/netp"
)

type SGAnalyzer struct {
	sgResource   *types.SecurityGroup
	ingressRules []*SGRule
	egressRules  []*SGRule
	// rules are the default ones; that is, no rules were specified manually
	isDefault           bool
	ingressConnectivity *ConnectivityResult
	egressConnectivity  *ConnectivityResult
	sgMap               map[string]*SecurityGroup
	referencedIPblocks  []*ipblock.IPBlock
}

func NewSGAnalyzer(sg *types.SecurityGroup) *SGAnalyzer {
	res := &SGAnalyzer{sgResource: sg}
	return res
}

func isIngressRule(direction *string) bool {
	if direction == nil {
		return false
	}
	if *direction == "inbound" {
		return true
	}
	return false
}

func getEmptyConnSet() *connection.Set {
	return connection.None()
}

func getAllConnSet() *connection.Set {
	return connection.All()
}

func getProperty(p *int64, defaultP int64) int64 {
	if p == nil {
		return defaultP
	}
	return *p
}

func getTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *connection.Set {
	protocol := netp.ProtocolStringUDP
	if p == protocolTCP {
		protocol = netp.ProtocolStringTCP
	}
	return connection.TCPorUDPConnection(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
}

func (sga *SGAnalyzer) getProtocolAllRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *SGRule, err error) {
	ruleRes = &SGRule{}
	protocol := *ruleObj.IpProtocol

	connStr := fmt.Sprintf("protocol: %s", protocol)
	ruleRes.ipRanges = ipblock.New()
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		ruleRes.ipRanges = ruleRes.ipRanges.Union(ipRange)
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.ipRanges.String())
	ruleRes.connections = getAllConnSet()
	return ruleStr, ruleRes, nil
}

func (sga *SGAnalyzer) getProtocolTcpudpRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	dstPortMin := getProperty(&minPort, connection.MinPort)
	dstPortMax := getProperty(&maxPort, connection.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.IpProtocol, dstPorts)
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		ruleRes.ipRanges = ruleRes.ipRanges.Union(ipRange)
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.ipRanges.String())
	ruleRes = &SGRule{
		// TODO: src ports can be considered here?
		connections: getTCPUDPConns(*ruleObj.IpProtocol,
			connection.MinPort,
			connection.MaxPort,
			dstPortMin,
			dstPortMax,
		),
	}
	return ruleStr, ruleRes, nil
}

func getRuleStr(direction, connStr, ipRanges string) string {
	return fmt.Sprintf("direction: %s,  conns: %s, ipRanges: %s\n", direction, connStr, ipRanges)
}

func getICMPconn(icmpType, icmpCode *int64) *connection.Set {
	typeMin := getProperty(icmpType, connection.MinICMPType)
	typeMax := getProperty(icmpType, connection.MaxICMPType)
	codeMin := getProperty(icmpCode, connection.MinICMPCode)
	codeMax := getProperty(icmpCode, connection.MaxICMPCode)
	return connection.ICMPConnection(typeMin, typeMax, codeMin, codeMax)
}

func (sga *SGAnalyzer) getProtocolIcmpRule(ruleObj *types.IpPermission, direction string) (
	ruleStr string, ruleRes *SGRule, err error) {
	minPort := int64(*ruleObj.FromPort)
	maxPort := int64(*ruleObj.ToPort)
	conns := getICMPconn(&minPort, &maxPort)
	connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.IpProtocol, conns)
	for i := range ruleObj.IpRanges {
		ipRange, err := ipblock.FromCidr(*ruleObj.IpRanges[i].CidrIp)
		if err != nil {
			return "", nil, err
		}
		ruleRes.ipRanges = ruleRes.ipRanges.Union(ipRange)
	}
	ruleStr = getRuleStr(direction, connStr, ruleRes.ipRanges.String())
	ruleRes = &SGRule{
		connections: conns,
	}
	return
}

func (sga *SGAnalyzer) getSGRule(index int) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	var ruleObj types.IpPermission
	direction := inbound
	if index < len(sga.sgResource.IpPermissions) {
		isIngress = true
		ruleObj = sga.sgResource.IpPermissions[index]
	} else {
		direction = outbound
		isIngress = false
		ruleObj = sga.sgResource.IpPermissionsEgress[index-len(sga.sgResource.IpPermissions)]
	}
	switch *ruleObj.IpProtocol {
	case "-1": // all protocols
		ruleStr, ruleRes, err = sga.getProtocolAllRule(&ruleObj, direction)
	case "tcp":
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case "udp":
		ruleStr, ruleRes, err = sga.getProtocolTcpudpRule(&ruleObj, direction)
	case "icmp":
		ruleStr, ruleRes, err = sga.getProtocolIcmpRule(&ruleObj, direction)
	default:
		return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
	}
	if err != nil {
		return "", nil, false, err
	}
	ruleRes.index = index
	return fmt.Sprintf("index: %d, %v", index, ruleStr), ruleRes, isIngress, nil
}

func (sga *SGAnalyzer) getSGrules(sgObj *types.SecurityGroup) (ingressRules, egressRules []*SGRule, err error) {
	ingressRules = []*SGRule{}
	egressRules = []*SGRule{}
	rules := append(sgObj.IpPermissions, sgObj.IpPermissionsEgress...)
	for index := range rules {
		_, ruleObj, isIngress, err := sga.getSGRule(index)
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

type SGRule struct {
	connections *connection.Set
	ipRanges    *ipblock.IPBlock
	index       int // index of original rule in *types.SecurityGroup.IpPermissions and *types.SecurityGroup.IpPermissionsEgress
}

func (cr *ConnectivityResult) string() string {
	res := []string{}
	for t, conn := range cr.allowedConns {
		res = append(res, fmt.Sprintf("remote: %s, conn: %s", t.ToIPRanges(), conn.String()))
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func analyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	remotes := []*ipblock.IPBlock{}
	for i := range rules {
		if rules[i].ipRanges != nil {
			remotes = append(remotes, rules[i].ipRanges)
		}
	}
	disjointTargets := ipblock.DisjointIPBlocks(remotes, []*ipblock.IPBlock{ipblock.GetCidrAll()})
	res := &ConnectivityResult{isIngress: isIngress, allowedConns: map[*ipblock.IPBlock]*connection.Set{},
		allowRules: map[*ipblock.IPBlock][]int{}}
	for i := range disjointTargets {
		res.allowedConns[disjointTargets[i]] = getEmptyConnSet()
		res.allowRules[disjointTargets[i]] = []int{}
	}
	for i := range rules {
		rule := rules[i]
		conn := rule.connections
		for disjointTarget := range res.allowedConns {
			if disjointTarget.ContainedIn(rule.ipRanges) {
				res.allowedConns[disjointTarget] = res.allowedConns[disjointTarget].Union(conn)
				res.allowRules[disjointTarget] = append(res.allowRules[disjointTarget], rule.index)
			}
		}
	}

	return res
}

func (sga *SGAnalyzer) prepareAnalyzer(sgMap map[string]*SecurityGroup, currentSg *SecurityGroup) error {
	if len(currentSg.members) == 0 {
		return nil // avoid analysis sg which is not applied to any members
	}
	var err error
	sga.sgMap = sgMap
	if sga.ingressRules, sga.egressRules, err = sga.getSGrules(sga.sgResource); err != nil {
		return err
	}
	sga.ingressConnectivity = analyzeSGRules(sga.ingressRules, true)
	sga.egressConnectivity = analyzeSGRules(sga.egressRules, false)
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
	egressRuleCidrs := egressRule.ipRanges.ToCidrList()
	if len(egressRuleCidrs) != 1 {
		return false
	}
	if egressRuleCidrs[0] == ipblock.CidrAll && egressRule.connections.IsAll() {
		return true
	}
	return false
}

func (sga *SGAnalyzer) AllowedConnectivity(target *ipblock.IPBlock, isIngress bool) *connection.Set {
	analyzedConns := sga.ingressOrEgressConnectivity(isIngress)
	for definedTarget, conn := range analyzedConns.allowedConns {
		if target.ContainedIn(definedTarget) {
			return conn
		}
	}

	return connection.None()
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity, if the required connection exists
//  1. The required connection (src/dst) is detected, if exists.
//  2. If connection is part of the query: is the required connection contained in the existing connection?
//     if it does, then the contributing rules are detected: rules that intersect the required connection
//     otherwise, the answer to the query is "no" and nil is returned
func (sga *SGAnalyzer) rulesFilterInConnectivity(target *ipblock.IPBlock, connQuery *connection.Set, isIngress bool) ([]int, error) {
	analyzedConns := sga.ingressOrEgressConnectivity(isIngress)
	for definedTarget, rules := range analyzedConns.allowRules {
		if target.ContainedIn(definedTarget) {
			if connQuery == nil {
				return rules, nil // connection not part of query - all rules are relevant
			}
			// connection is part of the query
			// the required connection - conn - should intersect with the existing connection
			// Namely, connection for the required protocol exists (one can query a single protocol)
			// on a nonempty set of the subnets
			intersectConn := connQuery.Intersect(analyzedConns.allowedConns[definedTarget])
			if intersectConn.IsEmpty() {
				return nil, nil
			}
			return sga.getRulesRelevantConn(rules, connQuery)
		}
	}
	return nil, nil
}

// given a list of rules and a connection, return the sublist of rules that contributes to the connection
func (sga *SGAnalyzer) getRulesRelevantConn(rules []int, conn *connection.Set) ([]int, error) {
	relevantRules := []int{}
	for _, rule := range append(sga.ingressRules, sga.egressRules...) {
		if slices.Contains(rules, rule.index) && !conn.Intersect(rule.connections).IsEmpty() {
			relevantRules = append(relevantRules, rule.index)
		}
	}
	return relevantRules, nil
}

func (sga *SGAnalyzer) ingressOrEgressConnectivity(isIngress bool) *ConnectivityResult {
	if isIngress {
		return sga.ingressConnectivity
	}
	return sga.egressConnectivity
}

// StringRules returns a string with the details of the specified rules
func (sga *SGAnalyzer) StringRules(rules []int) string {
	strRulesSlice := make([]string, len(rules))
	for i, ruleIndex := range rules {
		strRule, _, _, err := sga.getSGRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRulesSlice[i] = "\t" + strRule
	}
	sort.Strings(strRulesSlice)
	return strings.Join(strRulesSlice, "")
}
