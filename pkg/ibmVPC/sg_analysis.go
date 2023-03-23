package ibmvpc

import (
	"fmt"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
	v1 "k8s.io/api/core/v1"
)

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
	res := common.MakeConnectionSet(false)
	return &res
}

func getAllConnSet() *common.ConnectionSet {
	res := common.MakeConnectionSet(true)
	return &res
}

func getProtocolConn(Protocol *string, PortMax, PortMin *int64) *common.ConnectionSet {
	res := getEmptyConnSet()
	ports := common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *PortMin, End: *PortMax}}}}
	if *Protocol == "tcp" {
		res.AddConnection(v1.ProtocolTCP, ports)
	}
	return res
}

func getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (*common.IPBlock, string) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	var target *common.IPBlock
	var cidr string
	var cidrRes string
	//TODO: handle other remote types:
	//SecurityGroupRuleRemoteIP
	//SecurityGroupRuleRemoteSecurityGroupReference
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
		cidr = *remoteObj.CIDRBlock
		target = common.NewIPBlockFromCidr(cidr)
	}
	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		if remoteObj.CIDRBlock == nil {
			return nil, ""
		}
		cidr = *remoteObj.CIDRBlock
		target = common.NewIPBlockFromCidr(cidr)
		cidrRes = target.ToCidrList()[0]
	}
	return target, cidrRes
}

func getSGRule(rule vpc1.SecurityGroupRuleIntf) (string, *SGRule, bool) {
	ruleRes := &SGRule{}
	var isIngress bool

	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolAll); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		var target *common.IPBlock
		//SecurityGroupRuleRemoteCIDR
		if target, cidr = getRemoteCidr(remote); target != nil {
			ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s\n", direction, protocol, cidr)
			//fmt.Printf("SG rule: %s\n", ruleStr)
			ruleRes.target = target
			ruleRes.connections = getAllConnSet()
			return ruleStr, ruleRes, isIngress
		}

	}
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		//protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		var target *common.IPBlock
		target, cidr = getRemoteCidr(remote)
		conns := common.MakeConnectionSet(false)
		ports := common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *ruleObj.PortMin, End: *ruleObj.PortMax}}}}
		if *ruleObj.Protocol == "tcp" {
			conns.AllowedProtocols[v1.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == "udp" {
			conns.AllowedProtocols[v1.ProtocolUDP] = &ports
		}

		dstPorts := fmt.Sprintf("%d-%d", *ruleObj.PortMin, *ruleObj.PortMax)
		connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
		ruleStr := fmt.Sprintf("direction: %s,  conns: %s, cidr: %s\n", direction, connStr, cidr)
		//fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &SGRule{}
		ruleRes.connections = getProtocolConn(ruleObj.Protocol, ruleObj.PortMax, ruleObj.PortMin)
		ruleRes.target = target
		return ruleStr, ruleRes, isIngress
	}

	return "", nil, false

}

func getSGDetails(sgObj *vpc1.SecurityGroup) string {
	res := ""
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		ruleStr, _, _ := getSGRule(rule)
		res += ruleStr
	}
	return res
}

func getSGrules(sgObj *vpc1.SecurityGroup) ([]*SGRule, []*SGRule) {
	ingressRules := []*SGRule{}
	egressRules := []*SGRule{}
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		_, ruleObj, isIngress := getSGRule(rule)
		if ruleObj == nil {
			continue
		}
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules
}

type SGRule struct {
	target      *common.IPBlock
	connections *common.ConnectionSet
	// add pointer to original rule
}

// ConnectivityResult should be built on disjoint ip-blocks for targets of all relevant sg results
// ConnectivityResult is per VSI network interface: contains allowed connectivity (with connection attributes) per target
type ConnectivityResult struct {
	isIngress    bool
	allowedconns map[*common.IPBlock]*common.ConnectionSet // allowed target and its allowed connections
}

func (cr *ConnectivityResult) union(cr2 *ConnectivityResult) *ConnectivityResult {
	// union based on disjoint ip-blocks of targets
	crTargets := cr.getTargets()
	cr2Targets := cr2.getTargets()
	disjointTargets := common.DisjointIPBlocks(crTargets, cr2Targets)
	res := &ConnectivityResult{isIngress: cr.isIngress, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
		for t, conn := range cr.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Union(*conn)
			}
		}
		for t, conn := range cr2.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Union(*conn)
			}
		}
	}

	return res
}

func (cr *ConnectivityResult) intersection(cr2 *ConnectivityResult) *ConnectivityResult {
	crTargets := cr.getTargets()
	cr2Targets := cr2.getTargets()
	disjointTargets := common.DisjointIPBlocks(crTargets, cr2Targets)
	res := &ConnectivityResult{isIngress: cr.isIngress, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
		for t, conn := range cr.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Union(*conn)
			}
		}
		for t, conn := range cr2.allowedconns {
			if disjointTargets[i].ContainedIn(t) {
				res.allowedconns[disjointTargets[i]].Intersection(*conn)
			}
		}
	}

	return res
}

func (cr *ConnectivityResult) string() string {
	res := ""
	for t, conn := range cr.allowedconns {
		res += fmt.Sprintf("target: %s, conn: %s\n", t.ToIPRanges(), conn.String())
	}
	return res
}

func (cr *ConnectivityResult) getTargets() []*common.IPBlock {
	res := []*common.IPBlock{}
	for t := range cr.allowedconns {
		res = append(res, t)
	}
	return res
}

func AnalyzeSGRules(rules []*SGRule, isIngress bool) *ConnectivityResult {
	targets := []*common.IPBlock{}
	for i := range rules {
		if rules[i].target != nil {
			targets = append(targets, rules[i].target)
		}
	}
	disjointTargets := common.DisjointIPBlocks(targets, []*common.IPBlock{(common.NewIPBlockFromCidr("0.0.0.0/0"))})
	res := &ConnectivityResult{isIngress: isIngress, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
	for i := range disjointTargets {
		res.allowedconns[disjointTargets[i]] = getEmptyConnSet()
	}
	for i := range rules {
		rule := rules[i]
		target := rule.target
		conn := rule.connections
		for disjointTarget := range res.allowedconns {
			if disjointTarget.ContainedIn(target) {
				res.allowedconns[disjointTarget].Union(*conn)
			}

		}
	}

	return res

}

func AnalyzeSG(vsiIP *common.IPBlock, sg *vpc1.SecurityGroup) (*ConnectivityResult, *ConnectivityResult) {
	ingressRules, egressRules := getSGrules(sg)
	ingressRes := AnalyzeSGRules(ingressRules, true)
	egressRes := AnalyzeSGRules(egressRules, false)
	return ingressRes, egressRes
}

/*
create an object that can return the value for
AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet

*/

type SGAnalyzer struct {
	sgResource          *vpc1.SecurityGroup
	ingressRules        []*SGRule
	egressRules         []*SGRule
	ingressConnectivity *ConnectivityResult
	egressConnectivity  *ConnectivityResult
}

func NewSGAnalyzer(sg *vpc1.SecurityGroup) *SGAnalyzer {
	res := &SGAnalyzer{sgResource: sg}
	res.ingressRules, res.egressRules = getSGrules(sg)
	res.ingressConnectivity = AnalyzeSGRules(res.ingressRules, true)
	res.egressConnectivity = AnalyzeSGRules(res.egressRules, true)
	return res
}

func (sga *SGAnalyzer) AllowedConnectivity(target string, isIngress bool) *common.ConnectionSet {
	ipb := common.NewIPBlockFromCidr(target)
	var analyzedConns *ConnectivityResult
	if isIngress {
		analyzedConns = sga.ingressConnectivity
	} else {
		analyzedConns = sga.egressConnectivity
	}
	for definedTarget, conn := range analyzedConns.allowedconns {
		if ipb.ContainedIn(definedTarget) {
			return conn
		}
	}
	return vpcmodel.NoConns()
}
