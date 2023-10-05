package ibmvpc

import (
	"fmt"
	"sort"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	connection "github.com/np-guard/connectionlib/pkg/connection"
	ipblock "github.com/np-guard/connectionlib/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type NACLAnalyzer struct {
	naclResource *vpc1.NetworkACL
	ingressRules []*NACLRule
	egressRules  []*NACLRule
	// analysis results
	analyzedSubnets    map[string]*AnalysisResultPerSubnet
	referencedIPblocks []*ipblock.IPBlock
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

func getProperty(p *int64, defaultP int64) int64 {
	if p == nil {
		return defaultP
	}
	return *p
}

func getTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *connection.Set {
	conns := connection.NewSet(false)
	protocol := connection.ProtocolUDP
	if p == protocolTCP {
		protocol = connection.ProtocolTCP
	}
	conns.AddTCPorUDP(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
	return conns
}

func getNACLRule(rule vpc1.NetworkACLRuleItemIntf) (connStr string, ruleRes *NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var direction, src, dst, action string
	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		conns = connection.NewSet(true)
		connStr = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		conns = getTCPUDPConns(*ruleObj.Protocol,
			getProperty(ruleObj.SourcePortMin, connection.MinPort),
			getProperty(ruleObj.SourcePortMax, connection.MaxPort),
			getProperty(ruleObj.DestinationPortMin, connection.MinPort),
			getProperty(ruleObj.DestinationPortMax, connection.MaxPort),
		)
		srcPorts := getPortsStr(*ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := getPortsStr(*ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr = fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
		conns, _ = getICMPconn(ruleObj.Type, ruleObj.Code)
		connStr = fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	default:
		err = fmt.Errorf("getNACLRule unsupported type for rule: %s ", rule)
		return "", nil, false, err
	}

	srcIP, err := ipblock.New(src, []string{})
	if err != nil {
		return "", nil, false, err
	}
	dstIP, err := ipblock.New(dst, []string{})
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &NACLRule{src: srcIP, dst: dstIP, connections: conns, action: action}
	isIngress = direction == inbound
	connStr = fmt.Sprintf("direction: %s , src: %s , dst: %s, conn: %s, action: %s\n",
		direction, src, dst, connStr, action)
	return connStr, ruleRes, isIngress, nil
}

type NACLRule struct {
	src         *ipblock.IPBlock
	dst         *ipblock.IPBlock
	connections *connection.Set
	action      string
	// TODO: add pointer to the original rule
	// add ingress/egress ?
}

func (r *NACLRule) dumpRule() string {
	return fmt.Sprintf("src: %s, dst: %s, conn: %s, action: %s", r.src.ToIPRanges(), r.dst.ToIPRanges(), r.connections.String(), r.action)
}

var _ = (*NACLAnalyzer).dumpNACLrules // avoiding "unused" warning

func (na *NACLAnalyzer) dumpNACLrules() string {
	res := "ingress rules:\n"
	ingressList := []string{}
	for _, r := range na.ingressRules {
		ingressList = append(ingressList, r.dumpRule())
	}
	egressList := []string{}
	for _, r := range na.egressRules {
		egressList = append(egressList, r.dumpRule())
	}
	res += strings.Join(ingressList, "\n")
	res += "\negress rules:\n"
	res += strings.Join(egressList, "\n")
	return res
}

// given ingress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *ipblock.IPBlock,
	disjointPeers []*ipblock.IPBlock, isIngress bool,
) map[string]*connection.Set {
	allowedIngress := map[string]*connection.Set{}
	deniedIngress := map[string]*connection.Set{}
	for _, cidr := range disjointPeers {
		ranges := strings.Join(cidr.ToIPRanges(), ",")
		if cidr.ContainedIn(subnetCidr) {
			allowedIngress[ranges] = getEmptyConnSet()
			deniedIngress[ranges] = getEmptyConnSet()
		}
	}

	if src.ContainedIn(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				ranges := strings.Join(cidr.ToIPRanges(), ",")
				allowedIngress[ranges] = getAllConnSet()
			}
		}
		return allowedIngress
	}

	for _, ingressRule := range rules {
		var s *ipblock.IPBlock
		var d *ipblock.IPBlock
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
		destCidrList := []*ipblock.IPBlock{}
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(destCidr) {
				destCidrList = append(destCidrList, cidr)
			}
		}
		for _, disjointDestCidr := range destCidrList {
			ranges := strings.Join(disjointDestCidr.ToIPRanges(), ",")
			if ingressRule.action == "allow" {
				addedAllowedConns := ingressRule.connections.Copy()
				addedAllowedConns = addedAllowedConns.Subtract(deniedIngress[ranges])
				// issue here at union below
				allowedIngress[ranges] = allowedIngress[ranges].Union(addedAllowedConns)
			} else if ingressRule.action == "deny" {
				addedDeniedConns := ingressRule.connections.Copy()
				addedDeniedConns = addedDeniedConns.Subtract(allowedIngress[ranges])
				deniedIngress[ranges] = deniedIngress[ranges].Union(addedDeniedConns)
			}
		}
	}
	return allowedIngress
}

func getDisjointPeersForIngressOrEgressAnalysis(
	rules []*NACLRule, subnet *ipblock.IPBlock, isIngress bool) (
	disjointSrcPeers,
	disjointDstPeers []*ipblock.IPBlock) {
	var srcPeers, dstPeers []*ipblock.IPBlock
	srcPeers = make([]*ipblock.IPBlock, 1+len(rules))
	dstPeers = make([]*ipblock.IPBlock, 1+len(rules))
	cidrAll := ipblock.GetCIDRAll()
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
		disjointSrcPeers = ipblock.DisjointIPBlocks(srcPeers, []*ipblock.IPBlock{ipblock.GetCIDRAll()})
		disjointDstPeers = ipblock.DisjointIPBlocks(dstPeers, []*ipblock.IPBlock{subnet})
	} else {
		disjointSrcPeers = ipblock.DisjointIPBlocks(srcPeers, []*ipblock.IPBlock{subnet})
		disjointDstPeers = ipblock.DisjointIPBlocks(dstPeers, []*ipblock.IPBlock{ipblock.GetCIDRAll()})
	}
	return
}

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *ipblock.IPBlock) (disjointSrcPeers, disjointDstPeers []*ipblock.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, true)
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *ipblock.IPBlock) (disjointSrcPeers, disjointDstPeers []*ipblock.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, false)
}

// get connectivity result for each disjoint target in the subnet
func (na *NACLAnalyzer) AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *ipblock.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				if dstIP, err := ipblock.FromIPRangeStr(dst); err == nil {
					ranges := strings.Join(dstIP.ToIPRanges(), ",")
					if connRes, ok := res[ranges]; ok {
						connRes.allowedconns[src] = conn
					} else {
						res[ranges] = &ConnectivityResult{isIngress: true, allowedconns: map[*ipblock.IPBlock]*connection.Set{}}
						res[ranges].allowedconns[src] = conn
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
			if srcIP, err := ipblock.FromIPRangeStr(src); err == nil {
				ranges := strings.Join(srcIP.ToIPRanges(), ",")
				if connRes, ok := res[ranges]; ok {
					connRes.allowedconns[dst] = conn
				} else {
					res[ranges] = &ConnectivityResult{isIngress: true, allowedconns: map[*ipblock.IPBlock]*connection.Set{}}
					res[ranges].allowedconns[dst] = conn
				}
			}
		}
	}

	return res
}

// func (na *NACLAnalyzer) dumpNACLRules()

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

func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *ipblock.IPBlock,
	isIngress bool, subnetDisjointTarget *ipblock.IPBlock,
) (string, *ConnectivityResult) {
	res := []string{}
	connResult := &ConnectivityResult{isIngress: isIngress}
	connResult.allowedconns = map[*ipblock.IPBlock]*connection.Set{}
	if subnetDisjointTarget == nil {
		connResult = nil
	}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				ranges := strings.Join(src.ToIPRanges(), ",")
				res = append(res, getConnStr(ranges, dst, conn.String()))
				dstIP, err := ipblock.FromIPRangeStr(dst)
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
			ranges := strings.Join(dst.ToIPRanges(), ",")
			res = append(res, getConnStr(src, ranges, conn.String()))
			srcIP, err := ipblock.FromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(srcIP) {
				connResult.allowedconns[dst] = conn
			}
		}
	}
	return strings.Join(res, ""), connResult
}

// TODO: return a map from each possible subnetDisjointTarget to its ConnectivityResult, instead of a specific ConnectivityResult
// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func (na *NACLAnalyzer) AnalyzeNACL(subnet *ipblock.IPBlock) (
	ingressResConnectivity, egressResConnectivity map[string]*ConnectivityResult) {
	ingressResConnectivity = na.AnalyzeNACLRulesPerDisjointTargets(na.ingressRules, subnet, true)
	egressResConnectivity = na.AnalyzeNACLRulesPerDisjointTargets(na.egressRules, subnet, false)
	return ingressResConnectivity, egressResConnectivity
}

// this function adds the analysis of certain subnet connectivity based on the the NACL
// it saves the analysis results in na.analyzedSubnets
func (na *NACLAnalyzer) addAnalysisPerSubnet(subnetCidr string) {
	if _, ok := na.analyzedSubnets[subnetCidr]; ok {
		return
	}
	subnetCidrIPBlock, err := ipblock.FromCIDR(subnetCidr)
	_ = err
	ingressRes, egressRes := na.AnalyzeNACL(subnetCidrIPBlock)
	na.analyzedSubnets[subnetCidr] = NewAnalysisResultPerSubnet(subnetCidr, ingressRes, egressRes)
}

// GeneralConnectivityPerSubnet returns the str of the connectivity for analyzed subnet input
func (na *NACLAnalyzer) GeneralConnectivityPerSubnet(subnetCidr string) (
	strResult string,
	connectivityObjResult map[string]*vpcmodel.IPbasedConnectivityResult,
) {
	na.addAnalysisPerSubnet(subnetCidr)

	strResult = "Subnet: " + subnetCidr + "\n"
	ingressRes := na.analyzedSubnets[subnetCidr].ingressRes
	egressRes := na.analyzedSubnets[subnetCidr].egressRes
	connectivityObjResult = map[string]*vpcmodel.IPbasedConnectivityResult{}

	// map from disjointSubnetCidr to its connectivity str
	strResPerSubnetSection := map[string]string{}

	for disjointSubnetCidr, connectivityRes := range ingressRes {
		// assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		// TODO: currently assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].IngressAllowedConns = connectivityRes.allowedconns
		strResPerSubnetSection[disjointSubnetCidr] = "Ingress Connectivity:\n" + connectivityRes.string()
	}

	for disjointSubnetCidr, connectivityRes := range egressRes {
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].EgressAllowedConns = connectivityRes.allowedconns
		strResPerSubnetSection[disjointSubnetCidr] += "\nEgress Connectivity:\n" + connectivityRes.string()
	}
	keys := make([]string, len(strResPerSubnetSection))
	i := 0
	for key := range strResPerSubnetSection {
		keys[i] = key
		i += 1
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(keys) > 1 {
			strResult += "\nlocal range within subnet: " + key + "\n"
		}
		strResult += strResPerSubnetSection[key] + "\n"
	}
	return strResult, connectivityObjResult
}

// AllowedConnectivity returns set of allowed connections given src/dst and direction
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) AllowedConnectivity(subnetCidr, inSubentCidr, target string, isIngress bool) (*connection.Set, error) {
	var analyzedConns map[string]*ConnectivityResult
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)

	na.addAnalysisPerSubnet(subnetCidr)
	if isIngress {
		analyzedConns = na.analyzedSubnets[subnetCidr].ingressRes
	} else {
		analyzedConns = na.analyzedSubnets[subnetCidr].egressRes
	}
	targetIPblock, err := ipblock.FromCIDROrAddress(target)
	if err != nil {
		return nil, err
	}
	inSubnetIPblock, err := ipblock.FromCIDROrAddress(inSubentCidr)
	if err != nil {
		return nil, err
	}

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := ipblock.FromIPRangeStr(disjointSubnetCidr)
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
