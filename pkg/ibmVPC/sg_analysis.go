package ibmvpc

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
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

func getProtocolConn(Protocol *string, PortMax, PortMin *int64) (*common.ConnectionSet, error) {
	res := getEmptyConnSet()
	ports := common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *PortMin, End: *PortMax}}}}
	var err error
	switch *Protocol {
	case "tcp":
		res.AddConnection(common.ProtocolTCP, ports)
	case "udp":
		res.AddConnection(common.ProtocolUDP, ports)
	case "icmp":
		res.AddConnection(common.ProtocolICMP, ports)
	default:
		err = fmt.Errorf("getProtocolConn: unknown protocol %s .", *Protocol)
	}

	return res, err
}

func (sga *SGAnalyzer) getRemoteCidr(remote vpc1.SecurityGroupRuleRemoteIntf) (*common.IPBlock, string, error) {
	// TODO: on actual run from SG example, the type of remoteObj is SecurityGroupRuleRemote and not SecurityGroupRuleRemoteCIDR,
	// even if cidr is defined
	var target *common.IPBlock
	var cidr string
	var cidrRes string
	//TODO: handle other remote types:
	//SecurityGroupRuleRemoteIP
	//SecurityGroupRuleRemoteSecurityGroupReference
	/*if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemoteCIDR); ok {
		cidr = *remoteObj.CIDRBlock
		target = common.NewIPBlockFromCidr(cidr)
		return nil, "", fmt.Errorf("sg error getRemoteCidr: unexpected type for remoteObj: SecurityGroupRuleRemoteCIDR ")
	}*/
	// how can infer type of remote from this object?
	// can also be Address or CRN or ...
	if remoteObj, ok := remote.(*vpc1.SecurityGroupRuleRemote); ok {
		/*if remoteObj.CIDRBlock == nil {
			return nil, ""
		}*/
		if remoteObj.CIDRBlock != nil {
			cidr = *remoteObj.CIDRBlock
			target = common.NewIPBlockFromCidr(cidr)
			cidrRes = target.ToCidrList()[0]
		} else if remoteObj.Address != nil {
			address := *remoteObj.Address
			target, _ = common.NewIPBlockFromIPAddress(address)
			cidrRes = target.ToCidrList()[0]
		} else if remoteObj.Name != nil {
			if remoteSg, ok := sga.sgMap[*remoteObj.Name]; ok {
				resIpBlock := &common.IPBlock{}
				for member := range remoteSg.members {
					memberIpBlock, err := common.NewIPBlockFromIPAddress(member)
					if err != nil {
						return nil, "", err
					}
					resIpBlock = resIpBlock.Union(memberIpBlock)
				}
				target = resIpBlock
				cidrRes = strings.Join(target.ToCidrList(), ",")
			}

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

func (sga *SGAnalyzer) getSGRule(rule vpc1.SecurityGroupRuleIntf) (string, *SGRule, bool, error) {
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
		target, cidr, err := sga.getRemoteCidr(remote)
		if err == nil {
			if target == nil {
				return "", nil, false, fmt.Errorf("getSGRule error: empty target in rule %+v", rule)
			}
			ruleStr := fmt.Sprintf("direction: %s, protocol: %s, cidr: %s\n", direction, protocol, cidr)
			//fmt.Printf("SG rule: %s\n", ruleStr)
			ruleRes.target = target
			ruleRes.connections = getAllConnSet()
			return ruleStr, ruleRes, isIngress, nil
		}
		return "", nil, false, err
	}
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		//protocol := *ruleObj.Protocol
		remote := ruleObj.Remote
		cidr := ""
		var target *common.IPBlock
		target, cidr, err := sga.getRemoteCidr(remote)
		if err != nil {
			return "", nil, false, err
		}
		conns := common.MakeConnectionSet(false)
		ports := common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *ruleObj.PortMin, End: *ruleObj.PortMax}}}}
		if *ruleObj.Protocol == "tcp" {
			conns.AllowedProtocols[common.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == "udp" {
			conns.AllowedProtocols[common.ProtocolUDP] = &ports
		}

		dstPorts := fmt.Sprintf("%d-%d", *ruleObj.PortMin, *ruleObj.PortMax)
		connStr := fmt.Sprintf("protocol: %s,  dstPorts: %s", *ruleObj.Protocol, dstPorts)
		ruleStr := fmt.Sprintf("direction: %s,  conns: %s, cidr: %s\n", direction, connStr, cidr)
		//fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &SGRule{}
		ruleRes.connections, err = getProtocolConn(ruleObj.Protocol, ruleObj.PortMax, ruleObj.PortMin)
		if err != nil {
			return ruleStr, ruleRes, isIngress, err
		}
		ruleRes.target = target
		return ruleStr, ruleRes, isIngress, nil
	}
	//SecurityGroupRuleSecurityGroupRuleProtocolIcmp
	if ruleObj, ok := rule.(*vpc1.SecurityGroupRuleSecurityGroupRuleProtocolIcmp); ok {
		direction := *ruleObj.Direction
		isIngress = isIngressRule(ruleObj.Direction)
		cidr := ""
		remote := ruleObj.Remote
		var target *common.IPBlock
		target, cidr, err := sga.getRemoteCidr(remote)
		if err != nil {
			return "", nil, false, err
		}
		conns := common.MakeConnectionSet(false)
		icmpType := ruleObj.Type
		// TODO: handle also icmp code
		var icmpTypeProperties common.PortSet
		if icmpType == nil {
			icmpTypeProperties = common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: 0, End: 255}}}}
		} else {
			icmpTypeProperties = common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *icmpType, End: *icmpType}}}}
		}
		conns.AllowedProtocols[common.ProtocolICMP] = &icmpTypeProperties

		icmpTypeStr := icmpTypeProperties.String()
		connStr := fmt.Sprintf("protocol: %s,  icmpType: %s", *ruleObj.Protocol, icmpTypeStr)
		ruleStr := fmt.Sprintf("direction: %s,  conns: %s, cidr: %s\n", direction, connStr, cidr)
		//fmt.Printf("SG rule: %s\n", ruleStr)
		ruleRes := &SGRule{}
		ruleRes.connections, err = getProtocolConn(ruleObj.Protocol, &icmpTypeProperties.Ports.IntervalSet[0].End, &icmpTypeProperties.Ports.IntervalSet[0].Start)
		if err != nil {
			return ruleStr, ruleRes, isIngress, err
		}
		ruleRes.target = target
		return ruleStr, ruleRes, isIngress, nil

	}

	return "", nil, false, fmt.Errorf("getSGRule error: unsupported type")

}

/*func getSGDetails(sgObj *vpc1.SecurityGroup) string {
	res := ""
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		ruleStr, _, _ := getSGRule(rule)
		res += ruleStr
	}
	return res
}*/

func (sga *SGAnalyzer) getSGrules(sgObj *vpc1.SecurityGroup) ([]*SGRule, []*SGRule, error) {
	ingressRules := []*SGRule{}
	egressRules := []*SGRule{}
	for index := range sgObj.Rules {
		rule := sgObj.Rules[index]
		_, ruleObj, isIngress, err := sga.getSGRule(rule)
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

/*func AnalyzeSG(vsiIP *common.IPBlock, sg *vpc1.SecurityGroup) (*ConnectivityResult, *ConnectivityResult) {
	ingressRules, egressRules := getSGrules(sg)
	ingressRes := AnalyzeSGRules(ingressRules, true)
	egressRes := AnalyzeSGRules(egressRules, false)
	return ingressRes, egressRes
}*/

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
	sgMap               map[string]*SecurityGroup
	referencedIPblocks  []*common.IPBlock
}

func NewSGAnalyzer(sg *vpc1.SecurityGroup) *SGAnalyzer {
	res := &SGAnalyzer{sgResource: sg}
	/*res.ingressRules, res.egressRules = getSGrules(sg)
	res.ingressConnectivity = AnalyzeSGRules(res.ingressRules, true)
	res.egressConnectivity = AnalyzeSGRules(res.egressRules, true)*/
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
	fmt.Printf("\nprepareAnalyzer results:\n")
	fmt.Printf("sg: %s\n", currentSg.Name())
	fmt.Println("ingressConnectivity:")
	fmt.Printf("%s", sga.ingressConnectivity.string())
	fmt.Println("egressConnectivity:")
	fmt.Printf("%s", sga.egressConnectivity.string())
	fmt.Println("-----")

	return nil
}

func (sga *SGAnalyzer) AllowedConnectivity(target string, isIngress bool) *common.ConnectionSet {
	ipb := common.NewIPBlockFromCidrOrAddress(target)

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
