package resources

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"
	v1 "k8s.io/api/core/v1"
)

func getNACLRule(rule vpc1.NetworkACLRuleItemIntf) (string, *NACLRule, bool) {
	ruleRes := NACLRule{}
	var isIngress bool

	if ruleObj, ok := rule.(*vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll); ok {
		res := fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n", *ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, *ruleObj.Protocol, *ruleObj.Action)
		// convert to rule object
		srcIP, _ := NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := NewIPBlock(*ruleObj.Destination, []string{})
		conns := MakeConnectionSet(true)
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
		srcIP, _ := NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := NewIPBlock(*ruleObj.Destination, []string{})
		conns := MakeConnectionSet(false)
		ports := PortSet{Ports: CanonicalIntervalSet{IntervalSet: []Interval{{Start: *ruleObj.DestinationPortMin, End: *ruleObj.DestinationPortMax}}}}
		if *ruleObj.Protocol == "tcp" {
			conns.AllowedProtocols[v1.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == "udp" {
			conns.AllowedProtocols[v1.ProtocolUDP] = &ports
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
	src         *IPBlock
	dst         *IPBlock
	connections *ConnectionSet
	action      string
}

func getEmptyConnSet() *ConnectionSet {
	res := MakeConnectionSet(false)
	return &res
}

func getAllConnSet() *ConnectionSet {
	res := MakeConnectionSet(true)
	return &res
}

// given ingress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*NACLRule, src *IPBlock, subnetCidr *IPBlock, disjointPeers []*IPBlock, isIngress bool) map[string]*ConnectionSet {
	allowedIngress := map[string]*ConnectionSet{}
	deniedIngress := map[string]*ConnectionSet{}
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
		var s *IPBlock
		var d *IPBlock
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
		destCidrList := []*IPBlock{}
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

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *IPBlock) ([]*IPBlock, []*IPBlock) {
	srcPeers := []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}
	dstPeers := []*IPBlock{subnet}
	//peers := []*IPBlock{subnet}
	for _, rule := range rules {
		//peers = append(peers, rule.src)
		//peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return DisjointIPBlocks(srcPeers, []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}), DisjointIPBlocks(dstPeers, []*IPBlock{subnet})
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *IPBlock) ([]*IPBlock, []*IPBlock) {
	dstPeers := []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))}
	srcPeers := []*IPBlock{subnet}
	//peers := []*IPBlock{subnet}
	for _, rule := range rules {
		//peers = append(peers, rule.src)
		//peers = append(peers, rule.dst)
		srcPeers = append(srcPeers, rule.src)
		dstPeers = append(dstPeers, rule.dst)
	}
	return DisjointIPBlocks(srcPeers, []*IPBlock{subnet}), DisjointIPBlocks(dstPeers, []*IPBlock{(NewIPBlockFromCidr("0.0.0.0/0"))})
}

//get ingress and egress rules from NACL obj
func getNACLRules(naclObj *vpc1.NetworkACL) ([]*NACLRule, []*NACLRule) {
	ingressRules := []*NACLRule{}
	egressRules := []*NACLRule{}
	for index := range naclObj.Rules {
		rule := naclObj.Rules[index]
		_, ruleObj, isIngress := getNACLRule(rule)
		if rule == nil {
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

func AnalyzeNACLRules(rules []*NACLRule, subnet *IPBlock, isIngress bool) string {

	res := []string{}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, fmt.Sprintf("%s => %s : %s\n", src.ToIPRanges(), dst, conn.String()))
			}
		}
		return strings.Join(res, "")
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, fmt.Sprintf("%s => %s : %s\n", src, dst.ToIPRanges(), conn.String()))
		}
	}
	return strings.Join(res, "")

}

// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func AnalyzeNACL(naclObj *vpc1.NetworkACL, subnet *IPBlock) (string, string) {
	ingressRules, egressRules := getNACLRules(naclObj)
	ingressRes := AnalyzeNACLRules(ingressRules, subnet, true)
	egressRes := AnalyzeNACLRules(egressRules, subnet, false)
	return ingressRes, egressRes
}

func Test() {

}
