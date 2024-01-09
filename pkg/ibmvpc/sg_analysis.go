package ibmvpc

import (
	"fmt"
	"sort"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
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
	referencedIPblocks  []*common.IPBlock
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

func getEmptyConnSet() *common.ConnectionSet {
	return common.NewConnectionSet(false)
}

func getAllConnSet() *common.ConnectionSet {
	return common.NewConnectionSet(true)
}

func (sga *SGAnalyzer) getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (*common.IPBlock, string, error) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	var target *common.IPBlock
	var cidr string
	var cidrRes string
	//TODO: handle other remote types:
	// SecurityGroupRuleRemoteIP
	// SecurityGroupRuleRemoteSecurityGroupReference

	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		switch {
		case remoteObj.CIDRBlock != nil:
			cidr = *remoteObj.CIDRBlock
			target = common.NewIPBlockFromCidr(cidr)
			cidrRes = target.ToCidrList()[0]
		case remoteObj.Address != nil:
			address := *remoteObj.Address
			target, _ = common.NewIPBlockFromIPAddress(address)
			cidrRes = target.ToCidrList()[0]
		case remoteObj.Name != nil:
			if remoteSg, ok := sga.sgMap[*remoteObj.Name]; ok {
				resIPBlock := &common.IPBlock{}
				for member := range remoteSg.members {
					memberIPBlock, err := common.NewIPBlockFromIPAddress(member)
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
	var target *common.IPBlock
	// SecurityGroupRuleRemoteCIDR
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
	var target *common.IPBlock
	target, cidr, err = sga.getRemoteCidr(remote)
	if err != nil {
		return "", nil, false, err
	}

	dstPortMin := getProperty(ruleObj.PortMin, common.MinPort)
	dstPortMax := getProperty(ruleObj.PortMax, common.MaxPort)
	dstPorts := fmt.Sprintf("%d-%d", dstPortMin, dstPortMax)
	connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
	ruleStr = getRuleStr(direction, connStr, cidr)
	ruleRes = &SGRule{
		// TODO: src ports can be considered here?
		connections: getTCPUDPConns(*ruleObj.Protocol,
			common.MinPort,
			common.MaxPort,
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

func getICMPconn(icmpType, icmpCode *int64) (connsRes *common.ConnectionSet, icmpConnStr string) {
	conns := common.NewConnectionSet(false)
	typeMin := getProperty(icmpType, common.MinICMPtype)
	typeMax := getProperty(icmpType, common.MaxICMPtype)
	codeMin := getProperty(icmpCode, common.MinICMPcode)
	codeMax := getProperty(icmpCode, common.MaxICMPcode)

	conns.AddICMPConnection(typeMin, typeMax, codeMin, codeMax)
	icmpConnStr = conns.String()
	return conns, icmpConnStr
}

func (sga *SGAnalyzer) getProtocolIcmpRule(ruleObj *vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	direction := *ruleObj.Direction
	isIngress = isIngressRule(ruleObj.Direction)
	cidr := ""
	remote := ruleObj.Remote
	var target *common.IPBlock
	target, cidr, err = sga.getRemoteCidr(remote)
	if err != nil {
		return "", nil, false, err
	}
	conns, icmpTypeStr := getICMPconn(ruleObj.Type, ruleObj.Code)
	connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.Protocol, icmpTypeStr)
	ruleStr = getRuleStr(direction, connStr, cidr)
	ruleRes = &SGRule{}
	ruleRes.connections = conns
	ruleRes.target = target
	return ruleStr, ruleRes, isIngress, nil
}

func (sga *SGAnalyzer) getSGRule(index int) (
	ruleStr string, ruleRes *SGRule, isIngress bool, err error) {
	rule := sga.sgResource.Rules[index]
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll); ok {
		ruleStr, ruleRes, isIngress, err = sga.getProtocolAllRule(ruleObj)
	}
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp); ok {
		ruleStr, ruleRes, isIngress, err = sga.getProtocolTcpudpRule(ruleObj)
	}
	// SecurityGroupRuleSecurityGroupRuleProtocolIcmp
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp); ok {
		ruleStr, ruleRes, isIngress, err = sga.getProtocolIcmpRule(ruleObj)
	}
	if err == nil {
		ruleRes.index = index
		return fmt.Sprintf("index: %d, %v", index, ruleStr), ruleRes, isIngress, nil
	}

	return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")
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
	target      *common.IPBlock
	connections *common.ConnectionSet
	index       int // index of original rule in *vpc1.SecurityGroup.Rules
}

// ConnectivityResult should be built on disjoint ip-blocks for targets of all relevant sg results
// ConnectivityResult is per VSI network interface: contains allowed connectivity (with connection attributes) per target
type ConnectivityResult struct {
	isIngress    bool
	allowedconns map[*common.IPBlock]*common.ConnectionSet // allowed target and its allowed connections
	contribRules map[*common.IPBlock][]int                 // indexes of contribRules contributing to this connectivity
}

func (cr *ConnectivityResult) string() string {
	res := []string{}
	for t, conn := range cr.allowedconns {
		res = append(res, fmt.Sprintf("remote: %s, conn: %s", t.ToIPRanges(), conn.String()))
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func AnalyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	targets := []*common.IPBlock{}
	for i := range rules {
		if rules[i].target != nil {
			targets = append(targets, rules[i].target)
		}
	}
	disjointTargets := common.DisjointIPBlocks(targets, []*common.IPBlock{common.GetCidrAll()})
	res := &ConnectivityResult{isIngress: isIngress, allowedconns: map[*common.IPBlock]*common.ConnectionSet{},
		contribRules: map[*common.IPBlock][]int{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
		res.contribRules[disjointTargets[i]] = []int{}
	}
	for i := range rules {
		rule := rules[i]
		target := rule.target
		conn := rule.connections
		for disjointTarget := range res.allowedconns {
			if disjointTarget.ContainedIn(target) {
				res.allowedconns[disjointTarget] = res.allowedconns[disjointTarget].Union(conn)
				res.contribRules[disjointTarget] = append(res.contribRules[disjointTarget], rule.index)
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
	if egressRuleCidrs[0] == common.CidrAll && egressRule.connections.AllowAll {
		return true
	}
	return false
}

func (sga *SGAnalyzer) AllowedConnectivity(target string, isIngress bool) *common.ConnectionSet {
	analyzedConns, ipb := sga.getAnalyzedConnsIPB(target, isIngress)
	for definedTarget, conn := range analyzedConns.allowedconns {
		if ipb.ContainedIn(definedTarget) {
			return conn
		}
	}
	return vpcmodel.NoConns()
}

// rulesInConnectivity list of SG rules contributing to the connectivity
func (sga *SGAnalyzer) rulesInConnectivity(target string, conn *common.ConnectionSet, isIngress bool) ([]int, error) {
	analyzedConns, ipb := sga.getAnalyzedConnsIPB(target, isIngress)
	for definedTarget, rules := range analyzedConns.contribRules {
		if ipb.ContainedIn(definedTarget) {
			definedTargetConn := analyzedConns.allowedconns[definedTarget]
			if conn != nil { // connection not part of the query
			     definedTargetConn := analyzedConns.allowedconns[definedTarget]
				contained, err := conn.ContainedIn(definedTargetConn)
				if err != nil {
					return nil, err
				}
				if contained {
					return sga.getRulesRelevantConn(rules, conn)
				}
				return nil, nil
			}
			return rules, nil // connection not part of query
		}
	}
	return nil, nil
}

// given a list of rules and a connection, return the sublist of rules that contributes to the connection
func (sga *SGAnalyzer) getRulesRelevantConn(rules []int, conn *common.ConnectionSet) ([]int, error) {
	relevantRules := []int{}
	allRules := sga.ingressRules
	allRules = append(allRules, sga.egressRules...)
	for _, rule := range allRules {
		if contains(rules, rule.index) && !conn.Intersection(rule.connections).IsEmpty() {
			relevantRules = append(relevantRules, rule.index)
		}
	}
	return relevantRules, nil
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (sga *SGAnalyzer) getAnalyzedConnsIPB(target string, isIngress bool) (res *ConnectivityResult, ipb *common.IPBlock) {
	ipb = common.NewIPBlockFromCidrOrAddress(target)
	if isIngress {
		return sga.ingressConnectivity, ipb
	}
	return sga.egressConnectivity, ipb
}

// StringRules returns a string with the details of the specified rules
func (sga *SGAnalyzer) StringRules(rules []int) string {
	var strRules string
	for _, ruleIndex := range rules {
		strRule, _, _, err := sga.getSGRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRules += "\t" + strRule
	}
	return strRules
}
