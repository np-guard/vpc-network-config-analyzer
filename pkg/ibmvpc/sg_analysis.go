package ibmvpc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

type SGAnalyzer struct {
	sgResource   *vpc1.SecurityGroup
	ingressRules []*SGRule
	egressRules  []*SGRule
	// rules are the default ones; that is, no rules were specified manually
	isDefault           bool
	ingressConnectivity *ConnectivityResult
	egressConnectivity  *ConnectivityResult
	sgMap               map[string]*SecurityGroup
	referencedIPblocks  []*ipblock.IPBlock
}

func NewSGAnalyzer(sg *vpc1.SecurityGroup) *SGAnalyzer {
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

func (sga *SGAnalyzer) getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (*ipblock.IPBlock, string, error) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	var target *ipblock.IPBlock
	var cidr string
	var cidrRes string
	var err error
	//TODO: handle other remote types:
	// SecurityGroupRuleRemoteIP
	// SecurityGroupRuleRemoteSecurityGroupReference

	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		switch {
		case remoteObj.CIDRBlock != nil:
			cidr = *remoteObj.CIDRBlock
			target, err = ipblock.FromCidr(cidr)
			if err != nil {
				return nil, "", err
			}
			cidrRes = target.ToCidrList()[0]
		case remoteObj.Address != nil:
			address := *remoteObj.Address
			target, err = ipblock.FromIPAddress(address)
			if err != nil {
				return nil, "", err
			}
			cidrRes = target.ToCidrList()[0]
		case remoteObj.Name != nil:
			if remoteSg, ok := sga.sgMap[*remoteObj.Name]; ok {
				resIPBlock := ipblock.New()
				for member := range remoteSg.members {
					memberIPBlock, err := ipblock.FromIPAddress(member)
					if err != nil {
						return nil, "", err
					}
					resIPBlock = resIPBlock.Union(memberIPBlock)
				}
				target = resIPBlock
				cidrRes = strings.Join(target.ToCidrList(), ",")
			}
		default:
			return nil, "", fmt.Errorf("sg error: getRemoteCidr - SecurityGroupRuleRemote is empty: %+v", remoteObj)
		}

		if target == nil || cidrRes == "" {
			return target, cidrRes, fmt.Errorf("sg error: getRemoteCidr returns empty result. remoteObj: %+v", remoteObj)
		}
	}
	if target == nil || cidrRes == "" {
		return target, cidrRes, fmt.Errorf("sg error: getRemoteCidr returns empty result. could not convert remoteObj to expected type ")
	}

	sga.referencedIPblocks = append(sga.referencedIPblocks, target.Split()...)
	return target, cidrRes, nil
}

func (sga *SGAnalyzer) getProtocolAllRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	ruleRes = &SGRule{}
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	protocol := *ruleObj.Protocol
	remote := ruleObj.Remote
	cidr := ""
	var target *ipblock.IPBlock
	target, cidr, err = sga.getRemoteCidr(remote)
	if err == nil {
		if target == nil {
			return "", nil, false, fmt.Errorf("getSGRule error: empty target in rule %+v", ruleObj)
		}
		ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s\n", direction, protocol, cidr)
		ruleRes.target = target
		ruleRes.connections = getAllConnSet()
		return ruleStr, ruleRes, isIngress, nil
	}
	return "", nil, false, err
}

func (sga *SGAnalyzer) getProtocolTcpudpRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	remote := ruleObj.Remote
	cidr := ""
	var target *ipblock.IPBlock
	target, cidr, err = sga.getRemoteCidr(remote)
	if err != nil {
		return "", nil, false, err
	}

	dstPortMin := getProperty(ruleObj.PortMin, connection.MinPort)
	dstPortMax := getProperty(ruleObj.PortMax, connection.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
	ruleStr = getRuleStr(direction, connStr, cidr)
	ruleRes = &SGRule{
		// TODO: src ports can be considered here?
		connections: getTCPUDPConns(*ruleObj.Protocol,
			connection.MinPort,
			connection.MaxPort,
			dstPortMin,
			dstPortMax,
		),
		target: target,
	}
	return ruleStr, ruleRes, isIngress, nil
}

func getRuleStr(direction, connStr, cidr string) string {
	return fmt.Sprintf("direction: %s,  conns: %s, cidr: %s\n", direction, connStr, cidr)
}

func getICMPconn(icmpType, icmpCode *int64) *connection.Set {
	typeMin := getProperty(icmpType, connection.MinICMPType)
	typeMax := getProperty(icmpType, connection.MaxICMPType)
	codeMin := getProperty(icmpCode, connection.MinICMPCode)
	codeMax := getProperty(icmpCode, connection.MaxICMPCode)
	return connection.ICMPConnection(typeMin, typeMax, codeMin, codeMax)
}

func (sga *SGAnalyzer) getProtocolIcmpRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	target, cidr, err := sga.getRemoteCidr(ruleObj.Remote)
	if err != nil {
		return
	}
	conns := getICMPconn(ruleObj.Type, ruleObj.Code)
	connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.Protocol, conns)
	ruleStr = getRuleStr(*ruleObj.Direction, connStr, cidr)
	ruleRes = &SGRule{
		connections: conns,
		target:      target,
	}
	isIngress = isIngressRule(ruleObj.Direction)
	return
}

func (sga *SGAnalyzer) getSGRule(index int) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	rule := sga.sgResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolAllRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolTcpudpRule(ruleObj)
	case *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp:
		ruleStr, ruleRes, isIngress, err = sga.getProtocolIcmpRule(ruleObj)
	default:
		return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
	}
	if err != nil {
		return "", nil, false, err
	}
	ruleRes.index = index
	return fmt.Sprintf("index: %d, %v", index, ruleStr), ruleRes, isIngress, nil
}

func (sga *SGAnalyzer) getSGrules(sgObj *vpc1.SecurityGroup) (ingressRules, egressRules []*SGRule, err error) {
	ingressRules = []*SGRule{}
	egressRules = []*SGRule{}
	for index := range sgObj.Rules {
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
	target      *ipblock.IPBlock
	connections *connection.Set
	index       int // index of original rule in *vpc1.SecurityGroup.Rules
}

func (cr *ConnectivityResult) string() string {
	res := []string{}
	for t, conn := range cr.allowedConns {
		res = append(res, fmt.Sprintf("remote: %s, conn: %s", t.ToIPRanges(), conn.String()))
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func AnalyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	targets := []*ipblock.IPBlock{}
	for i := range rules {
		if rules[i].target != nil {
			targets = append(targets, rules[i].target)
		}
	}
	disjointTargets := ipblock.DisjointIPBlocks(targets, []*ipblock.IPBlock{ipblock.GetCidrAll()})
	res := &ConnectivityResult{isIngress: isIngress, allowedConns: map[*ipblock.IPBlock]*connection.Set{},
		allowRules: map[*ipblock.IPBlock][]int{}}
	for i := range disjointTargets {
		res.allowedConns[disjointTargets[i]] = getEmptyConnSet()
		res.allowRules[disjointTargets[i]] = []int{}
	}
	for i := range rules {
		rule := rules[i]
		target := rule.target
		conn := rule.connections
		for disjointTarget := range res.allowedConns {
			if disjointTarget.ContainedIn(target) {
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
	sga.ingressConnectivity = AnalyzeSGRules(sga.ingressRules, true)
	sga.egressConnectivity = AnalyzeSGRules(sga.egressRules, false)
	sga.isDefault = sga.areSGRulesDefault()
	return nil
}

// areSGRulesDefault are the rules equal to the default rules,
// defined as "deny all inbound traffic and permit all outbound traffic"
// namely, no inbound rules and a single outbound rule with target 0.0.0.0/0
func (sga *SGAnalyzer) areSGRulesDefault() bool {
	if len(sga.ingressRules) > 0 || len(sga.egressRules) != 1 {
		return false
	}
	egressRule := sga.egressRules[0]
	egressRuleCidrs := egressRule.target.ToCidrList()
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

func (sga *SGAnalyzer) ingressOrEgressConnectivity(isIngress bool) (res *ConnectivityResult) {
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
