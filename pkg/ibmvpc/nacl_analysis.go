package ibmvpc

import (
	"fmt"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type NACLAnalyzer struct {
	naclResource *vpc1.NetworkACL
	ingressRules []*NACLRule
	egressRules  []*NACLRule
	// analysis results
	analyzedSubnets    map[string]*AnalysisResultPerSubnet
	referencedIPblocks []*common.IPBlock
}

type AnalysisResultPerSubnet struct {
	subnet     string
	ingressRes map[string]*ConnectivityResult // map from disjoint-subnet-cidr to its analysis res (ingress)
	egressRes  map[string]*ConnectivityResult // map from disjoint-subnet-cidr  its analysis res (egress)
}

func NewAnalysisResultPerSubnet(subnet string, ingressRes, egressRes map[string]*ConnectivityResult) (res *AnalysisResultPerSubnet) {
	return &AnalysisResultPerSubnet{subnet: subnet, ingressRes: ingressRes, egressRes: egressRes}
}

func NewNACLAnalyzer(nacl *vpc1.NetworkACL) (res *NACLAnalyzer, err error) {
	res = &NACLAnalyzer{
		naclResource:    nacl,
		analyzedSubnets: map[string]*AnalysisResultPerSubnet{},
	}
	res.ingressRules, res.egressRules, err = res.getNACLRules(nacl)
	return res, err
}

func getPortsStr(minPort, maxPort int64) string {
	return fmt.Sprintf("%d-%d", minPort, maxPort)
}

func getNACLRuleStr(direction, src, dst, conn, action string) string {
	return fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n",
		direction, src, dst, conn, action)
}

func getNACLRule(rule vpc1.NetworkACLRuleItemIntf) (ruleStr string, ruleObjRes *NACLRule, isIngressRes bool, err error) {
	ruleRes := NACLRule{}
	var isIngress bool

	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		res := getNACLRuleStr(*ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, *ruleObj.Protocol, *ruleObj.Action)
		// convert to rule object
		srcIP, _ := common.NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := common.NewIPBlock(*ruleObj.Destination, []string{})
		conns := common.MakeConnectionSet(true)
		ruleRes = NACLRule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == inbound {
			isIngress = true
		} else if *ruleObj.Direction == outbound {
			isIngress = false
		}
		return res, &ruleRes, isIngress, nil
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		srcPorts := getPortsStr(*ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := getPortsStr(*ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr := fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		res := getNACLRuleStr(*ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)

		// convert to rule object
		// TODO: currently ignoring src ports in the conversion
		srcIP, _ := common.NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := common.NewIPBlock(*ruleObj.Destination, []string{})
		conns := common.MakeConnectionSet(false)
		ports := common.PortSet{Ports: common.CanonicalIntervalSet{
			IntervalSet: []common.Interval{{Start: *ruleObj.DestinationPortMin, End: *ruleObj.DestinationPortMax}}},
		}
		if *ruleObj.Protocol == protocolTCP {
			conns.AllowedProtocols[common.ProtocolTCP] = &ports
		} else if *ruleObj.Protocol == protocolUDP {
			conns.AllowedProtocols[common.ProtocolUDP] = &ports
		}
		ruleRes = NACLRule{src: srcIP, dst: dstIP, connections: &conns, action: *ruleObj.Action}
		if *ruleObj.Direction == inbound {
			isIngress = true
		} else if *ruleObj.Direction == outbound {
			isIngress = false
		}
		return res, &ruleRes, isIngress, nil
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:

		connStr := fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
		res := getNACLRuleStr(*ruleObj.Direction, *ruleObj.Source, *ruleObj.Destination, connStr, *ruleObj.Action)
		conns, _ := getICMPconn(ruleObj.Type)
		srcIP, _ := common.NewIPBlock(*ruleObj.Source, []string{})
		dstIP, _ := common.NewIPBlock(*ruleObj.Destination, []string{})
		ruleRes = NACLRule{src: srcIP, dst: dstIP, connections: conns, action: *ruleObj.Action}
		if *ruleObj.Direction == inbound {
			isIngress = true
		} else if *ruleObj.Direction == outbound {
			isIngress = false
		}
		return res, &ruleRes, isIngress, nil
		// TODO: currently ignoring icmp rules and not converting to rule object
	default:
		return "", nil, false, fmt.Errorf("getNACLRule unsupported type for rule: %s ", rule)
	}
}

type NACLRule struct {
	src         *common.IPBlock
	dst         *common.IPBlock
	connections *common.ConnectionSet
	action      string
	// TODO: add pointer to the original rule
	// add ingress/egress ?
}

// given ingress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *common.IPBlock,
	disjointPeers []*common.IPBlock, isIngress bool,
) map[string]*common.ConnectionSet {
	allowedIngress := map[string]*common.ConnectionSet{}
	deniedIngress := map[string]*common.ConnectionSet{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedIngress[cidr.ToIPRanges()] = getEmptyConnSet()
		}
	}

	if src.ContainedIn(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
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

func getDisjointPeersForIngressOrEgressAnalysis(
	rules []*NACLRule, subnet *common.IPBlock, isIngress bool) (
	disjointSrcPeers,
	disjointDstPeers []*common.IPBlock) {
	var srcPeers, dstPeers []*common.IPBlock
	srcPeers = make([]*common.IPBlock, 1+len(rules))
	dstPeers = make([]*common.IPBlock, 1+len(rules))
	cidrAll := common.GetCidrAll()
	if isIngress {
		srcPeers[0] = cidrAll
		dstPeers[0] = subnet
	} else {
		srcPeers[0] = subnet
		dstPeers[0] = cidrAll
	}
	for i, rule := range rules {
		srcPeers[i+1] = rule.src
		dstPeers[i+1] = rule.dst
	}
	if isIngress {
		disjointSrcPeers = common.DisjointIPBlocks(srcPeers, []*common.IPBlock{common.GetCidrAll()})
		disjointDstPeers = common.DisjointIPBlocks(dstPeers, []*common.IPBlock{subnet})
	} else {
		disjointSrcPeers = common.DisjointIPBlocks(srcPeers, []*common.IPBlock{subnet})
		disjointDstPeers = common.DisjointIPBlocks(dstPeers, []*common.IPBlock{common.GetCidrAll()})
	}
	return
}

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *common.IPBlock) (disjointSrcPeers, disjointDstPeers []*common.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, true)
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *common.IPBlock) (disjointSrcPeers, disjointDstPeers []*common.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, false)
}

// get connectivity result for each disjoint target in the subnet
func (na *NACLAnalyzer) AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *common.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				if dstIP, err := common.IPBlockFromIPRangeStr(dst); err == nil {
					if connRes, ok := res[dstIP.ToIPRanges()]; ok {
						connRes.allowedconns[src] = conn
					} else {
						res[dstIP.ToIPRanges()] = &ConnectivityResult{isIngress: true, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
						res[dstIP.ToIPRanges()].allowedconns[src] = conn
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
				if connRes, ok := res[srcIP.ToIPRanges()]; ok {
					connRes.allowedconns[dst] = conn
				} else {
					res[srcIP.ToIPRanges()] = &ConnectivityResult{isIngress: true, allowedconns: map[*common.IPBlock]*common.ConnectionSet{}}
					res[srcIP.ToIPRanges()].allowedconns[dst] = conn
				}
			}
		}
	}

	return res
}

func (na *NACLAnalyzer) getNACLRules(naclObj *vpc1.NetworkACL) (ingressRules, egressRules []*NACLRule, err error) {
	ingressRules = []*NACLRule{}
	egressRules = []*NACLRule{}
	for index := range naclObj.Rules {
		rule := naclObj.Rules[index]
		_, ruleObj, isIngress, err := getNACLRule(rule)
		if err != nil {
			return nil, nil, err
		}
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
	return ingressRules, egressRules, nil
}

func getConnStr(src, dst, conn string) string {
	return fmt.Sprintf("%s => %s : %s\n", src, dst, conn)
}

func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *common.IPBlock,
	isIngress bool, subnetDisjointTarget *common.IPBlock,
) (string, *ConnectivityResult) {
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
				res = append(res, getConnStr(src.ToIPRanges(), dst, conn.String()))
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
		dstStr := strings.Join(dst.ToCidrList(), ",")
		fmt.Println(dstStr)
		allowedEgressConns := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, getConnStr(src, dst.ToIPRanges(), conn.String()))
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
func (na *NACLAnalyzer) AnalyzeNACL(naclObj *vpc1.NetworkACL, subnet *common.IPBlock) (
	ingressResConnectivity, egressResConnectivity map[string]*ConnectivityResult) {
	ingressResConnectivity = na.AnalyzeNACLRulesPerDisjointTargets(na.ingressRules, subnet, true)
	egressResConnectivity = na.AnalyzeNACLRulesPerDisjointTargets(na.egressRules, subnet, false)
	return ingressResConnectivity, egressResConnectivity
}

func (na *NACLAnalyzer) addAnalysisPerSubnet(subnetCidr string) {
	if _, ok := na.analyzedSubnets[subnetCidr]; ok {
		return
	}
	subnetCidrIPBlock := common.NewIPBlockFromCidr(subnetCidr)
	ingressRes, egressRes := na.AnalyzeNACL(na.naclResource, subnetCidrIPBlock)

	na.analyzedSubnets[subnetCidr] = NewAnalysisResultPerSubnet(subnetCidr, ingressRes, egressRes)

	fmt.Printf("\naddAnalysisPerSubnet results:\n")
	fmt.Printf("subnetCidr: %s\n", subnetCidr)
	subnetConnectivityResStr, _ := na.GeneralConnectivityPerSubnet(subnetCidr)
	fmt.Printf("%s", subnetConnectivityResStr)

	fmt.Println("-----")
}

func getDisjointSubnetCidrStr(disjointSubnetCidr string) string {
	return fmt.Sprintf("local ip-block: %s\n", disjointSubnetCidr)
}

// currently assuming only subnet-level connectivity result is required
// TODO: support refinement to partial subnet level when required
/*type SubnetConnectivityResult struct {
	allowedIngressConns map[*common.IPBlock]*common.ConnectionSet
	allowedEgressConns  map[*common.IPBlock]*common.ConnectionSet
}*/

func (na *NACLAnalyzer) GeneralConnectivityPerSubnet(subnetCidr string) (string, *vpcmodel.IPbasedConnectivityResult) {
	na.addAnalysisPerSubnet(subnetCidr)
	ingressRes := na.analyzedSubnets[subnetCidr].ingressRes
	egressRes := na.analyzedSubnets[subnetCidr].egressRes
	connectivityObjResult := &vpcmodel.IPbasedConnectivityResult{}
	strResult := "ingressConnectivity:\n"
	for disjointSubnetCidr, connectivityRes := range ingressRes {
		strResult += getDisjointSubnetCidrStr(disjointSubnetCidr)
		strResult += connectivityRes.string()
		//assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		connectivityObjResult.IngressAllowedConns = connectivityRes.allowedconns
	}
	strResult += "egressConnectivity:\n"
	for disjointSubnetCidr, connectivityRes := range egressRes {
		strResult += getDisjointSubnetCidrStr(disjointSubnetCidr)
		strResult += connectivityRes.string()
		connectivityObjResult.EgressAllowedConns = connectivityRes.allowedconns
	}
	return strResult, connectivityObjResult
}

func (na *NACLAnalyzer) AllowedConnectivity(subnetCidr, inSubentCidr, target string, isIngress bool) (*common.ConnectionSet, error) {
	var analyzedConns map[string]*ConnectivityResult
	//TODO: analyze per subnet disjoint cidrs and not necessarily entire subnet cidr
	na.addAnalysisPerSubnet(subnetCidr)
	if isIngress {
		analyzedConns = na.analyzedSubnets[subnetCidr].ingressRes
	} else {
		analyzedConns = na.analyzedSubnets[subnetCidr].egressRes
	}
	targetIPblock := common.NewIPBlockFromCidrOrAddress(target)
	inSubnetIPblock := common.NewIPBlockFromCidrOrAddress(inSubentCidr)

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := common.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, conn := range analyzedConnsPerCidr.allowedconns {
				if targetIPblock.ContainedIn(resTarget) {
					return conn, nil
				}
			}
		}
	}
	return nil, nil //TODO: add err here?
}
