package ibmvpc

import (
	"fmt"
	"slices"
	"sort"
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
	// todo: add ingress and egress explicitly denied
}

func NewAnalysisResultPerSubnet(subnet string, ingressRes, egressRes map[string]*ConnectivityResult) (res *AnalysisResultPerSubnet) {
	return &AnalysisResultPerSubnet{subnet: subnet, ingressRes: ingressRes, egressRes: egressRes}
}

func NewNACLAnalyzer(nacl *vpc1.NetworkACL) (res *NACLAnalyzer, err error) {
	res = &NACLAnalyzer{
		naclResource:    nacl,
		analyzedSubnets: map[string]*AnalysisResultPerSubnet{},
	}
	res.ingressRules, res.egressRules, err = res.getNACLRules()
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

func getTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *common.ConnectionSet {
	conns := common.NewConnectionSet(false)
	protocol := common.ProtocolUDP
	if p == protocolTCP {
		protocol = common.ProtocolTCP
	}
	conns.AddTCPorUDPConn(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
	return conns
}

func (na *NACLAnalyzer) getNACLRule(index int) (ruleStr string, ruleRes *NACLRule, isIngress bool, err error) {
	var conns *common.ConnectionSet
	var direction, src, dst, action string
	var connStr string
	rule := na.naclResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		conns = common.NewConnectionSet(true)
		connStr = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		conns = getTCPUDPConns(*ruleObj.Protocol,
			getProperty(ruleObj.SourcePortMin, common.MinPort),
			getProperty(ruleObj.SourcePortMax, common.MaxPort),
			getProperty(ruleObj.DestinationPortMin, common.MinPort),
			getProperty(ruleObj.DestinationPortMax, common.MaxPort),
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

	srcIP, err := common.NewIPBlock(src, []string{})
	if err != nil {
		return "", nil, false, err
	}
	dstIP, err := common.NewIPBlock(dst, []string{})
	if err != nil {
		return "", nil, false, err
	}
	ruleRes = &NACLRule{src: srcIP, dst: dstIP, connections: conns, action: action}
	isIngress = direction == inbound
	ruleStr = fmt.Sprintf("index: %d, direction: %s , src: %s , dst: %s, conn: %s, action: %s\n",
		index, direction, src, dst, connStr, action)
	return ruleStr, ruleRes, isIngress, nil
}

type NACLRule struct {
	src         *common.IPBlock
	dst         *common.IPBlock
	connections *common.ConnectionSet
	action      string
	index       int // index of original rule in *vpc1.NetworkACL
	// add ingress/egress ?
}

func (r *NACLRule) dumpRule() string {
	return fmt.Sprintf("index: %d, src: %s, dst: %s, conn: %s, action: %s",
		r.index, r.src.ToIPRanges(), r.dst.ToIPRanges(), r.connections.String(), r.action)
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

// given ingress/egress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks -- get the allowed connections
func getAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *common.IPBlock,
	disjointPeers []*common.IPBlock, isIngress bool,
) (allowedXgress map[string]*common.ConnectionSet, contribRules map[string][]int) {
	allowedXgress = map[string]*common.ConnectionSet{}
	deniedXgress := map[string]*common.ConnectionSet{}
	contribRules = map[string][]int{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			contribRules[cidr.ToIPRanges()] = []int{}
		}
	}

	if src.ContainedIn(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				allowedXgress[cidr.ToIPRanges()] = getAllConnSet()
			}
		}
		return allowedXgress, contribRules
	}

	for _, rule := range rules {
		var s *common.IPBlock
		var d *common.IPBlock
		if isIngress {
			s = rule.src
			d = rule.dst
		} else {
			s = rule.dst
			d = rule.src
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
			if rule.action == "allow" {
				addedAllowedConns := rule.connections.Copy()
				addedAllowedConns = addedAllowedConns.Subtract(deniedXgress[disjointDestCidr.ToIPRanges()])
				// issue here at union below
				allowedXgressDestCidrBefore := allowedXgress[disjointDestCidr.ToIPRanges()]
				allowedXgress[disjointDestCidr.ToIPRanges()] = allowedXgress[disjointDestCidr.ToIPRanges()].Union(addedAllowedConns)
				allowedXgressDestCidrAfter := allowedXgress[disjointDestCidr.ToIPRanges()]
				if !allowedXgressDestCidrAfter.Equal(allowedXgressDestCidrBefore) { // this rule contributes to the connection
					contribRules[disjointDestCidr.ToIPRanges()] = append(contribRules[disjointDestCidr.ToIPRanges()], rule.index)
				}
			} else if rule.action == "deny" {
				addedDeniedConns := rule.connections.Copy()
				addedDeniedConns = addedDeniedConns.Subtract(allowedXgress[disjointDestCidr.ToIPRanges()])
				deniedXgress[disjointDestCidr.ToIPRanges()] = deniedXgress[disjointDestCidr.ToIPRanges()].Union(addedDeniedConns)
			}
		}
	}
	return allowedXgress, contribRules
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

// AnalyzeNACLRulesPerDisjointTargets get connectivity result for each disjoint target in the subnet
func (na *NACLAnalyzer) AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *common.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	var disjointSrcPeers, disjointDstPeers []*common.IPBlock
	// the src/dst vars naming below are w.r.t. ingress; for egress it is the other way around
	if isIngress {
		disjointSrcPeers, disjointDstPeers = getDisjointPeersForIngressAnalysis(rules, subnet)
	} else {
		disjointDstPeers, disjointSrcPeers = getDisjointPeersForEgressAnalysis(rules, subnet)
	}
	for _, src := range disjointSrcPeers {
		allowedIngressConns, contribRules := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, isIngress)
		for dst, conn := range allowedIngressConns {
			if dstIP, err := common.IPBlockFromIPRangeStr(dst); err == nil {
				if connRes, ok := res[dstIP.ToIPRanges()]; ok {
					connRes.allowedconns[src] = conn
					connRes.contribRules[src] = contribRules[dst]
				} else {
					res[dstIP.ToIPRanges()] = &ConnectivityResult{isIngress: true, allowedconns: map[*common.IPBlock]*common.ConnectionSet{},
						contribRules: map[*common.IPBlock][]int{}}
					res[dstIP.ToIPRanges()].allowedconns[src] = conn
					// contribRules indexes are identical to these of allowedIngressConns, thus access legit
					res[dstIP.ToIPRanges()].contribRules[src] = contribRules[dst]
				}
			}
		}
	}
	return res
}

// func (na *NACLAnalyzer) dumpNACLRules()

func (na *NACLAnalyzer) getNACLRules() (ingressRules, egressRules []*NACLRule, err error) {
	ingressRules = []*NACLRule{}
	egressRules = []*NACLRule{}
	for index := range na.naclResource.Rules {
		rule := na.naclResource.Rules[index]
		_, ruleObj, isIngress, err := na.getNACLRule(index)
		if err != nil {
			return nil, nil, err
		}
		if rule == nil {
			continue
		}
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.src.Split()...)
		na.referencedIPblocks = append(na.referencedIPblocks, ruleObj.dst.Split()...)
		ruleObj.index = index
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
			allowedIngressConns, contribRules := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, getConnStr(src.ToIPRanges(), dst, conn.String()))
				dstIP, err := common.IPBlockFromIPRangeStr(dst)
				if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(dstIP) {
					connResult.allowedconns[src] = conn
					// the indexing of allowedIngressConns and contribRules are identical
					connResult.contribRules[src] = contribRules[dst]
				}
			}
		}
		return strings.Join(res, ""), connResult
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns, contribRules := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, getConnStr(src, dst.ToIPRanges(), conn.String()))
			srcIP, err := common.IPBlockFromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(srcIP) {
				connResult.allowedconns[dst] = conn
				// the indexing of allowedEgressConns and contribRules are identical
				connResult.contribRules[dst] = contribRules[src]
			}
		}
	}
	return strings.Join(res, ""), connResult
}

// TODO: return a map from each possible subnetDisjointTarget to its ConnectivityResult, instead of a specific ConnectivityResult
// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func (na *NACLAnalyzer) AnalyzeNACL(subnet *common.IPBlock) (
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
	subnetCidrIPBlock := common.NewIPBlockFromCidr(subnetCidr)
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

// initConnectivityRelatedCompute performs initial computation for AllowedConnectivity and rulesInConnectivity
func (na *NACLAnalyzer) initConnectivityRelatedCompute(subnetCidr, inSubentCidr, target string,
	isIngress bool) (analyzedConns map[string]*ConnectivityResult, targetIPblock, inSubnetIPblock *common.IPBlock) {
	na.addAnalysisPerSubnet(subnetCidr)
	if isIngress {
		analyzedConns = na.analyzedSubnets[subnetCidr].ingressRes
	} else {
		analyzedConns = na.analyzedSubnets[subnetCidr].egressRes
	}
	targetIPblock = common.NewIPBlockFromCidrOrAddress(target)
	inSubnetIPblock = common.NewIPBlockFromCidrOrAddress(inSubentCidr)
	return analyzedConns, targetIPblock, inSubnetIPblock
}

const notFoundMsg = "isIngress: %t , target %s, subnetCidr: %s, inSubentCidr %s, " +
	"could not find connectivity for given target + inSubentCidr"

// AllowedConnectivity returns set of allowed connections given src/dst and direction
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) AllowedConnectivity(subnetCidr, inSubentCidr, target string, isIngress bool) (*common.ConnectionSet, error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	analyzedConns, targetIPblock, inSubnetIPblock := na.initConnectivityRelatedCompute(subnetCidr, inSubentCidr, target, isIngress)

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
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, fmt.Errorf(notFoundMsg, isIngress, target, subnetCidr, inSubentCidr)
}

// rulesInConnectivity returns set of rules contributing to a connections given src/dst and direction
// if conn is specified then rules contributing to that connection; otherwise to any connection src->dst
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) rulesInConnectivity(subnetCidr, inSubentCidr,
	target string, conn *common.ConnectionSet, isIngress bool) ([]int, error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	analyzedConns, targetIPblock, inSubnetIPblock := na.initConnectivityRelatedCompute(subnetCidr, inSubentCidr, target, isIngress)

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := common.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, rules := range analyzedConnsPerCidr.contribRules {
				if targetIPblock.ContainedIn(resTarget) {
					if conn != nil { // connection is part of the query
						contained, err := conn.ContainedIn(analyzedConnsPerCidr.allowedconns[resTarget])
						if err != nil {
							return nil, err
						}
						if contained {
							return na.getRulesRelevantConn(rules, conn) // gets only rules relevant to conn
						}
						return nil, nil
					}
					return rules, nil
				}
			}
		}
	}
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, fmt.Errorf(notFoundMsg, isIngress, target, subnetCidr, inSubentCidr)
}

// given a list of rules and a connection, return the sublist of rules that contributes to the connection
func (na *NACLAnalyzer) getRulesRelevantConn(rules []int, conn *common.ConnectionSet) ([]int, error) {
	relevantRules := []int{}
	curConn := common.NewConnectionSet(false)
	for _, rule := range append(na.ingressRules, na.egressRules...) {
		if slices.Contains(rules, rule.index) && !conn.Intersection(rule.connections).IsEmpty() {
			curConn := curConn.Union(rule.connections)
			relevantRules = append(relevantRules, rule.index)
			contains, err := conn.ContainedIn(curConn)
			if err != nil {
				return nil, err
			}
			if contains { // of the required conn is contained in connections thus far, lower priority rules
				// are not relevant
				return relevantRules, nil
			}
		}
	}
	return relevantRules, nil
}

// StringRules returns a string with the details of the specified rules
func (na *NACLAnalyzer) StringRules(rules []int) string {
	var strRules string
	for _, ruleIndex := range rules {
		strRule, _, _, err := na.getNACLRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRules += "\t" + strRule
	}
	return strRules
}
