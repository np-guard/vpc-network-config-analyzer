package ibmvpc

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
)

func getNACLRule(rule vpc1.NetworkACLRuleItemIntf) (string, *NACLRule, bool) {
	ruleRes := NACLRule{}
	var isIngress bool

	if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll); ok {
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, *ruleObj.Protocol, *ruleObj.Action)
		// convert to rule object
		srcIP, _ := common.NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := common.NewIPBlock(*ruleObj.Destination, []string{})
		conns := common.MakeConnectionSet(true)
		ruleRes = NACLRule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == "inbound" {
			isIngress = true
		} else if *ruleObj.Direction == "outbound" {
			isIngress = false
		}
		return res, &ruleRes, isIngress
	} else if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp); ok {
		srcPorts := fmt.Sprintf("%d-%d", *ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := fmt.Sprintf("%d-%d", *ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr := fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)

		// convert to rule object
		// TODO: currently ignoring src ports in the conversion
		srcIP, _ := common.NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := common.NewIPBlock(*ruleObj.Destination, []string{})
		conns := common.MakeConnectionSet(false)
		ports := common.PortSet{Ports: common.CanonicalIntervalSet{IntervalSet: []common.Interval{{Start: *ruleObj.DestinationPortMin, End: *ruleObj.DestinationPortMax}}}}
		if *ruleObj.Protocol == "tcp" {
			conns.AllowedProtocols[common.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == "udp" {
			conns.AllowedProtocols[common.ProtocolUDP] = &ports
		}

		ruleRes = NACLRule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == "inbound" {
			isIngress = true
		} else if *ruleObj.Direction == "outbound" {
			isIngress = false
		}
		return res, &ruleRes, isIngress
		//return res, nil, false
	} else if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp); ok {
		connStr := fmt.Sprintf("protocol: %s, type: %d, code: %d", *ruleObj.Protocol, *ruleObj.Type, *ruleObj.Code)
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)

		// TODO: currently ignoring icmp rules and not converting to rule object

		return res, nil, false
	}
	return "", nil, false
}

type NACLRule struct {
	src         *common.IPBlock
	dst         *common.IPBlock
	connections *common.ConnectionSet
	action      string
	// TODO: add pointer to the original rule
	// add ingress/egress ?
}

/*func getEmptyConnSet() *common.ConnectionSet {
	res := common.MakeConnectionSet(false)
	return &res
}

func getAllConnSet() *common.ConnectionSet {
	res := common.MakeConnectionSet(true)
	return &res
}*/

// given ingress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*NACLRule, src *common.IPBlock, subnetCidr *common.IPBlock, disjointPeers []*common.IPBlock, isIngress bool) map[string]*common.ConnectionSet {
	allowedIngress := map[string]*common.ConnectionSet{}
	deniedIngress := map[string]*common.ConnectionSet{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
		}
	}

	if src.ContainedIn(subnetCidr) {
		//no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				allowedIngress[cidr.ToIPRanges()] = getAllConnSet()
			}
		}
		return allowedIngress
	}

	for _, ingressRule := range rules {
		var s *common.IPBlock
		var d *common.IPBlock
		if isIngress {
			s = ingressRule.src
			d = ingressRule.dst
		} else {
			s = ingressRule.dst
			d = ingressRule.src
		}
		if !src.ContainedIn(s) {
			continue
		}
		destCidr := d.Intersection(subnetCidr)
		// split destCidr to disjoint ip-blocks
		destCidrList := []*common.IPBlock{}
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(destCidr) {
				destCidrList = append(destCidrList, cidr)
			}
		}
		for _, disjointDestCidr := range destCidrList {
			if ingressRule.action == "allow" {
				addedAllowedConns := *ingressRule.connections.Copy()
				addedAllowedConns.Subtract(*deniedIngress[disjointDestCidr.ToIPRanges()])
				allowedIngress[disjointDestCidr.ToIPRanges()].Union(addedAllowedConns)
			} else if ingressRule.action == "deny" {
				addedDeniedConns := *ingressRule.connections.Copy()
				addedDeniedConns.Subtract(*allowedIngress[disjointDestCidr.ToIPRanges()])
				deniedIngress[disjointDestCidr.ToIPRanges()].Union(addedDeniedConns)
			}
		}
	}
	return allowedIngress
}

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *common.IPBlock) ([]*common.IPBlock, []*common.IPBlock) {
	srcPeers := []*common.IPBlock{(common.NewIPBlockFromCidr("0.0.0.0/0"))}
	dstPeers := []*common.IPBlock{subnet}
	//peers := []*IPBlock{subnet}
	for _, rule := range rules {
		//peers = append(peers, rule.src)
		//peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return common.DisjointIPBlocks(srcPeers, []*common.IPBlock{(common.NewIPBlockFromCidr("0.0.0.0/0"))}), common.DisjointIPBlocks(dstPeers, []*common.IPBlock{subnet})
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *common.IPBlock) ([]*common.IPBlock, []*common.IPBlock) {
	dstPeers := []*common.IPBlock{(common.NewIPBlockFromCidr("0.0.0.0/0"))}
	srcPeers := []*common.IPBlock{subnet}
	//peers := []*IPBlock{subnet}
	for _, rule := range rules {
		//peers = append(peers, rule.src)
		//peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return common.DisjointIPBlocks(srcPeers, []*common.IPBlock{subnet}), common.DisjointIPBlocks(dstPeers, []*common.IPBlock{(common.NewIPBlockFromCidr("0.0.0.0/0"))})
}

func getNACLDetails(naclObj *vpc1.NetworkACL) string {
	res := ""
	for index := range naclObj.Rules {
		rule := naclObj.Rules[index]
		ruleStr, _, _ := getNACLRule(rule)
		res += ruleStr
	}

	return res
}

//get ingress and egress rules from NACL obj
func (na *NACLAnalyzer) getNACLRules(naclObj *vpc1.NetworkACL) ([]*NACLRule, []*NACLRule) {
	ingressRules := []*NACLRule{}
	egressRules := []*NACLRule{}
	for index := range naclObj.Rules {
		rule := naclObj.Rules[index]
		_, ruleObj, isIngress := getNACLRule(rule)
		if rule == nil {
			continue
		}
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.src.Split()...)
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.dst.Split()...)
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules
}

// get connectivity result for each disjoint target in the subnet
func AnalyzeNACLRulesPerDisjointTargets(rules []*NACLRule, subnet *common.IPBlock, isIngress bool) map[*common.IPBlock]*ConnectivityResult {
	res := map[*common.IPBlock]*ConnectivityResult{}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				if dstIP, err := common.IPBlockFromIPRangeStr(dst); err == nil {
					if connRes, ok := res[dstIP]; ok {
						connRes.allowedconns[src] = conn
					} else {
						res[dstIP] = &ConnectivityResult{isIngress: true, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
						res[dstIP].allowedconns[src] = conn
					}
				}
			}
		}
		return res
	}
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			if srcIP, err := common.IPBlockFromIPRangeStr(src); err == nil {
				if connRes, ok := res[srcIP]; ok {
					connRes.allowedconns[dst] = conn
				} else {
					res[srcIP] = &ConnectivityResult{isIngress: true, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
					res[srcIP].allowedconns[dst] = conn
				}
			}
		}
	}

	return res
}

func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *common.IPBlock, isIngress bool, subnetDisjointTarget *common.IPBlock) (string, *ConnectivityResult) {
	res := []string{}
	connResult := &ConnectivityResult{isIngress: isIngress}
	connResult.allowedconns = map[*common.IPBlock]*common.ConnectionSet{}
	if subnetDisjointTarget == nil {
		connResult = nil
	}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, fmt.Sprintf("%s => %s : %s\n", src.ToIPRanges(), dst, conn.String()))
				dstIP, err := common.IPBlockFromIPRangeStr(dst)
				if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(dstIP) {
					connResult.allowedconns[src] = conn
				}
			}
		}
		return strings.Join(res, ""), connResult
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, fmt.Sprintf("%s => %s : %s\n", src, dst.ToIPRanges(), conn.String()))
			srcIP, err := common.IPBlockFromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(srcIP) {
				connResult.allowedconns[dst] = conn
			}
		}
	}
	return strings.Join(res, ""), connResult

}

// TODO: return a map from each possible subnetDisjointTarget to its ConnectivityResult, instead of a specific ConnectivityResult
// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func (na *NACLAnalyzer) AnalyzeNACL(naclObj *vpc1.NetworkACL, subnet *common.IPBlock, subnetDisjointTarget *common.IPBlock) (string, string, *ConnectivityResult, *ConnectivityResult) {
	//ingressRules, egressRules := getNACLRules(naclObj)
	ingressRes, ingressResConnectivity := na.AnalyzeNACLRules(na.ingressRules, subnet, true, subnetDisjointTarget)
	egressRes, egressResConnectivity := na.AnalyzeNACLRules(na.egressRules, subnet, false, subnetDisjointTarget)
	return ingressRes, egressRes, ingressResConnectivity, egressResConnectivity
}

/*func AnalyzeNACLPerDisjointTargets(naclObj *vpc1.NetworkACL, subnet *IPBlock) (*AnalysisConnectivityResults){

}*/

/*type AnalysisConnectivityResults struct {
	ingressRes map[*common.IPBlock]*ConnectivityResult
	egressRes  map[*common.IPBlock]*ConnectivityResult
}*/

type NACLAnalyzer struct {
	naclResource *vpc1.NetworkACL
	ingressRules []*NACLRule
	egressRules  []*NACLRule
	// analysis results
	ingressRes         map[string]*ConnectivityResult // map from cidr of subnet to its analysis res (ingress)
	egressRes          map[string]*ConnectivityResult // map from cidr of subnet to its analysis res (egress)
	referencedIPblocks []*common.IPBlock
}

func NewNACLAnalyzer(nacl *vpc1.NetworkACL) *NACLAnalyzer {
	res := &NACLAnalyzer{naclResource: nacl, ingressRes: map[string]*ConnectivityResult{}, egressRes: map[string]*ConnectivityResult{}}
	res.ingressRules, res.egressRules = res.getNACLRules(nacl)
	return res
}

func (na *NACLAnalyzer) addAnalysisPerSubnet(subnetCidr string) {
	subnetCidrIPBlock := common.NewIPBlockFromCidr(subnetCidr)
	//TODO: handle subnet disjoint target
	_, _, ingressRes, egressRes := na.AnalyzeNACL(na.naclResource, subnetCidrIPBlock, subnetCidrIPBlock)
	na.ingressRes[subnetCidr] = ingressRes
	na.egressRes[subnetCidr] = egressRes
}

func (na *NACLAnalyzer) AllowedConnectivity(subnetCidr, inSubentCidr, target string, isIngress bool) *common.ConnectionSet {
	var analyzedConns map[string]*ConnectivityResult
	//TODO: analyze per subnet disjoint cidrs and not necessarily entire subnet cidr
	na.addAnalysisPerSubnet(subnetCidr)
	if isIngress {
		analyzedConns = na.ingressRes
	} else {
		analyzedConns = na.egressRes
	}
	targetIPblock := common.NewIPBlockFromCidrOrAddress(target)

	if analyzedConnsPerSubnet, ok := analyzedConns[subnetCidr]; ok {
		for resTarget, conn := range analyzedConnsPerSubnet.allowedconns {
			if targetIPblock.ContainedIn(resTarget) {
				return conn
			}
		}
		return vpcmodel.NoConns()
	}
	return nil
}
