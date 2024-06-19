/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	ALLOW string = "allow"
	DENY  string = "deny"
)

type NACLAnalyzer struct {
	naclResource *vpc1.NetworkACL
	ingressRules []*NACLRule
	egressRules  []*NACLRule
	// analysis results
	analyzedSubnets    map[string]*AnalysisResultPerSubnet
	referencedIPblocks []*netset.IPBlock
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

func getTCPUDPConns(p string, srcPortMin, srcPortMax, dstPortMin, dstPortMax int64) *connection.Set {
	protocol := netp.ProtocolStringUDP
	if p == protocolTCP {
		protocol = netp.ProtocolStringTCP
	}
	return connection.NewTCPorUDP(protocol, srcPortMin, srcPortMax, dstPortMin, dstPortMax)
}

func (na *NACLAnalyzer) getNACLRule(index int) (ruleStr string, ruleRes *NACLRule, isIngress bool, err error) {
	var conns *connection.Set
	var direction, src, dst, action string
	var connStr string
	rule := na.naclResource.Rules[index]
	switch ruleObj := rule.(type) {
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolAll:
		conns = connection.All()
		connStr = *ruleObj.Protocol
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolTcpudp:
		conns = getTCPUDPConns(*ruleObj.Protocol,
			getProperty(ruleObj.SourcePortMin, netp.MinPort),
			getProperty(ruleObj.SourcePortMax, netp.MaxPort),
			getProperty(ruleObj.DestinationPortMin, netp.MinPort),
			getProperty(ruleObj.DestinationPortMax, netp.MaxPort),
		)
		srcPorts := getPortsStr(*ruleObj.SourcePortMin, *ruleObj.SourcePortMax)
		dstPorts := getPortsStr(*ruleObj.DestinationPortMin, *ruleObj.DestinationPortMax)
		connStr = fmt.Sprintf("protocol: %s, srcPorts: %s, dstPorts: %s", *ruleObj.Protocol, srcPorts, dstPorts)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	case *vpc1.NetworkACLRuleItemNetworkACLRuleProtocolIcmp:
		conns, err = connection.ICMPConnection(ruleObj.Type, ruleObj.Code)
		if err != nil {
			return "", nil, false, err
		}
		connStr = fmt.Sprintf("protocol: %s", *ruleObj.Protocol)
		direction = *ruleObj.Direction
		src = *ruleObj.Source
		dst = *ruleObj.Destination
		action = *ruleObj.Action
	default:
		err = fmt.Errorf("getNACLRule unsupported type for rule: %s ", rule)
		return "", nil, false, err
	}

	srcIP, dstIP, err := netset.PairCIDRsToIPBlocks(src, dst)
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
	src         *netset.IPBlock
	dst         *netset.IPBlock
	connections *connection.Set
	action      string
	index       int // index of original rule in *vpc1.NetworkACL
	// add ingress/egress ?
}

func (rule *NACLRule) dumpRule() string {
	return fmt.Sprintf("index: %d, src: %s, dst: %s, conn: %s, action: %s",
		rule.index, rule.src.ToIPRanges(), rule.dst.ToIPRanges(), common.LongString(rule.connections), rule.action)
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

// given ingress/egress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks --
// get the allowed connections, the relevant allow rules and relevant deny rules
func getAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *netset.IPBlock,
	disjointPeers []*netset.IPBlock, isIngress bool,
) (allowedXgress, deniedXgress map[string]*connection.Set, allowRules, denyRules map[string][]int) {
	allowedXgress = map[string]*connection.Set{}
	deniedXgress = map[string]*connection.Set{}
	allowRules = map[string][]int{}
	denyRules = map[string][]int{}
	for _, cidr := range disjointPeers {
		if cidr.IsSubset(subnetCidr) {
			allowedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			allowRules[cidr.ToIPRanges()] = []int{}
			denyRules[cidr.ToIPRanges()] = []int{}
		}
	}

	if src.IsSubset(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.IsSubset(subnetCidr) {
				allowedXgress[cidr.ToIPRanges()] = getAllConnSet()
			}
		}
		return allowedXgress, deniedXgress, allowRules, denyRules
	}

	for _, rule := range rules {
		s, d := rule.getSrcDst(isIngress)
		if !src.IsSubset(s) {
			continue
		}
		destCidr := d.Intersect(subnetCidr)
		// split destCidr to disjoint ip-blocks
		destCidrList := []*netset.IPBlock{}
		for _, cidr := range disjointPeers {
			if cidr.IsSubset(destCidr) {
				destCidrList = append(destCidrList, cidr)
			}
		}
		for _, disjointDestCidr := range destCidrList {
			disjointDestIP := disjointDestCidr.ToIPRanges()
			if rule.action == ALLOW {
				addedAllowedConns := rule.connections.Copy()
				addedAllowedConns = addedAllowedConns.Subtract(deniedXgress[disjointDestIP])
				// issue here at union below
				allowedXgressDestCidrBefore := allowedXgress[disjointDestIP]
				allowedXgress[disjointDestIP] = allowedXgress[disjointDestIP].Union(addedAllowedConns)
				if !allowedXgress[disjointDestIP].Equal(allowedXgressDestCidrBefore) { // this rule contributes to the connection
					allowRules[disjointDestIP] = append(allowRules[disjointDestIP], rule.index)
				}
			} else if rule.action == DENY {
				addedDeniedConns := rule.connections.Copy()
				addedDeniedConns = addedDeniedConns.Subtract(allowedXgress[disjointDestIP])
				deniedXgressDestCidrBefore := deniedXgress[disjointDestIP]
				deniedXgress[disjointDestIP] = deniedXgress[disjointDestIP].Union(addedDeniedConns)
				if !deniedXgress[disjointDestIP].Equal(deniedXgressDestCidrBefore) { // this deny rule is relevant to the connection
					denyRules[disjointDestIP] = append(denyRules[disjointDestIP], rule.index)
				}
			}
		}
	}
	return allowedXgress, deniedXgress, allowRules, denyRules
}

func (rule *NACLRule) getSrcDst(isIngress bool) (src, dst *netset.IPBlock) {
	if isIngress {
		return rule.src, rule.dst
	}
	return rule.dst, rule.src
}

func getDisjointPeersForIngressOrEgressAnalysis(
	rules []*NACLRule, subnet *netset.IPBlock, isIngress bool) (
	disjointSrcPeers,
	disjointDstPeers []*netset.IPBlock) {
	var srcPeers, dstPeers []*netset.IPBlock
	srcPeers = make([]*netset.IPBlock, 1+len(rules))
	dstPeers = make([]*netset.IPBlock, 1+len(rules))
	cidrAll := netset.GetCidrAll()
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
		disjointSrcPeers = netset.DisjointIPBlocks(srcPeers, []*netset.IPBlock{netset.GetCidrAll()})
		disjointDstPeers = netset.DisjointIPBlocks(dstPeers, []*netset.IPBlock{subnet})
	} else {
		disjointSrcPeers = netset.DisjointIPBlocks(srcPeers, []*netset.IPBlock{subnet})
		disjointDstPeers = netset.DisjointIPBlocks(dstPeers, []*netset.IPBlock{netset.GetCidrAll()})
	}
	return
}

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *netset.IPBlock) (srcPeers, dstPeers []*netset.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, true)
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *netset.IPBlock) (srcPeers, dstPeers []*netset.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, false)
}

// AnalyzeNACLRulesPerDisjointTargets get connectivity result for each disjoint target in the subnet
func AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *netset.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	var disjointSrcPeers, disjointDstPeers []*netset.IPBlock
	if isIngress {
		disjointSrcPeers, disjointDstPeers = getDisjointPeersForIngressAnalysis(rules, subnet)
	} else {
		disjointDstPeers, disjointSrcPeers = getDisjointPeersForEgressAnalysis(rules, subnet)
	}
	for _, srcIngDstEgr := range disjointSrcPeers {
		allowedIngressConns, deniedIngressConns,
			allowRules, denyRules := getAllowedXgressConnections(rules, srcIngDstEgr, subnet, disjointDstPeers, isIngress)
		updateAllowDeny(true, isIngress, allowedIngressConns, allowRules, srcIngDstEgr, res)
		updateAllowDeny(false, isIngress, deniedIngressConns, denyRules, srcIngDstEgr, res)
	}
	return res
}

func updateAllowDeny(allow, isIngress bool, xgressConn map[string]*connection.Set, rules map[string][]int,
	srcIngDstEgr *netset.IPBlock, res map[string]*ConnectivityResult) {
	for dstIngSrcEg, conn := range xgressConn {
		if dstIngSrcEgIPBlock, err := netset.IPBlockFromIPRangeStr(dstIngSrcEg); err == nil {
			dstIngSrcEgIPRange := dstIngSrcEgIPBlock.ToIPRanges()
			initConnectivityResult(res, dstIngSrcEgIPRange, isIngress)
			if allow {
				res[dstIngSrcEgIPRange].allowedConns[srcIngDstEgr] = conn
				// allowRules indexes are identical to these of allowedIngressConns, thus access legit
				res[dstIngSrcEgIPRange].allowRules[srcIngDstEgr] = rules[dstIngSrcEg]
			} else {
				res[dstIngSrcEgIPRange].deniedConns[srcIngDstEgr] = conn
				// allowRules indexes are identical to these of allowedIngressConns, thus access legit
				res[dstIngSrcEgIPRange].denyRules[srcIngDstEgr] = rules[dstIngSrcEg]
			}
		}
	}
}

func initConnectivityResult(connectivityMap map[string]*ConnectivityResult, indxToinit string, isIngress bool) {
	if _, ok := connectivityMap[indxToinit]; !ok {
		connectivityMap[indxToinit] = &ConnectivityResult{isIngress: isIngress,
			allowedConns: map[*netset.IPBlock]*connection.Set{}, allowRules: map[*netset.IPBlock][]int{},
			deniedConns: map[*netset.IPBlock]*connection.Set{}, denyRules: map[*netset.IPBlock][]int{}}
	}
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

// AnalyzeNACLRules todo: this is used only in testing. Did not expand for deny.
func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *netset.IPBlock,
	isIngress bool, subnetDisjointTarget *netset.IPBlock,
) (string, *ConnectivityResult) {
	res := []string{}
	connResult := &ConnectivityResult{isIngress: isIngress}
	connResult.allowedConns = map[*netset.IPBlock]*connection.Set{}
	connResult.deniedConns = map[*netset.IPBlock]*connection.Set{}
	if subnetDisjointTarget == nil {
		connResult = nil
	}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns, _, allowRules, _ := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, getConnStr(src.ToIPRanges(), dst, common.LongString(conn)))
				dstIP, err := netset.IPBlockFromIPRangeStr(dst)
				if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.IsSubset(dstIP) {
					connResult.allowedConns[src] = conn
					// the indexing of allowedIngressConns and allowRules are identical
					connResult.allowRules[src] = allowRules[dst]
				}
			}
		}
		return strings.Join(res, ""), connResult
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns, _, allowRules, _ := getAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, getConnStr(src, dst.ToIPRanges(), common.LongString(conn)))
			srcIP, err := netset.IPBlockFromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.IsSubset(srcIP) {
				connResult.allowedConns[dst] = conn
				// the indexing of allowedEgressConns and allowRules are identical
				connResult.allowRules[dst] = allowRules[src]
			}
		}
	}
	return strings.Join(res, ""), connResult
}

// TODO: return a map from each possible subnetDisjointTarget to its ConnectivityResult, instead of a specific ConnectivityResult
// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func (na *NACLAnalyzer) AnalyzeNACL(subnet *netset.IPBlock) (
	ingressResConnectivity, egressResConnectivity map[string]*ConnectivityResult) {
	ingressResConnectivity = AnalyzeNACLRulesPerDisjointTargets(na.ingressRules, subnet, true)
	egressResConnectivity = AnalyzeNACLRulesPerDisjointTargets(na.egressRules, subnet, false)
	return ingressResConnectivity, egressResConnectivity
}

// this function adds the analysis of certain subnet connectivity based on the the NACL
// it saves the analysis results in na.analyzedSubnets
func (na *NACLAnalyzer) addAnalysisPerSubnet(subnet *Subnet) {
	if _, ok := na.analyzedSubnets[subnet.cidr]; ok {
		return
	}
	ingressRes, egressRes := na.AnalyzeNACL(subnet.netset)
	na.analyzedSubnets[subnet.cidr] = NewAnalysisResultPerSubnet(subnet.cidr, ingressRes, egressRes)
}

// GeneralConnectivityPerSubnet returns the str of the connectivity for analyzed subnet input
func (na *NACLAnalyzer) GeneralConnectivityPerSubnet(subnet *Subnet) (
	strResult string,
	connectivityObjResult map[string]*vpcmodel.IPbasedConnectivityResult,
) {
	na.addAnalysisPerSubnet(subnet)

	strResult = "Subnet: " + subnet.cidr + "\n"
	ingressRes := na.analyzedSubnets[subnet.cidr].ingressRes
	egressRes := na.analyzedSubnets[subnet.cidr].egressRes
	connectivityObjResult = map[string]*vpcmodel.IPbasedConnectivityResult{}

	// map from disjointSubnetCidr to its connectivity str
	strResPerSubnetSection := map[string]string{}

	for disjointSubnetCidr, connectivityRes := range ingressRes {
		// assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		// TODO: currently assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].IngressAllowedConns = connectivityRes.allowedConns
		strResPerSubnetSection[disjointSubnetCidr] = "Ingress Connectivity:\n" + connectivityRes.string()
	}

	for disjointSubnetCidr, connectivityRes := range egressRes {
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].EgressAllowedConns = connectivityRes.allowedConns
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

// initConnectivityRelatedCompute performs initial computation for AllowedConnectivity and rulesFilterInConnectivity
func (na *NACLAnalyzer) initConnectivityRelatedCompute(subnet *Subnet, isIngress bool,
) (analyzedConns map[string]*ConnectivityResult) {
	na.addAnalysisPerSubnet(subnet)
	if isIngress {
		analyzedConns = na.analyzedSubnets[subnet.cidr].ingressRes
	} else {
		analyzedConns = na.analyzedSubnets[subnet.cidr].egressRes
	}
	return analyzedConns
}

const notFoundMsg = "isIngress: %t , target %s, subnetCidr: %s, inSubentCidr %s, " +
	"could not find connectivity for given target + inSubentCidr"

// TODO: Avoid some duplication of AllowedConnectivity & rulesFilterInConnectivity

// AllowedConnectivity returns set of allowed connections given src/dst and direction
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) AllowedConnectivity(subnet *Subnet, nodeInSubnet, targetNode vpcmodel.Node, isIngress bool) (
	*connection.Set, error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	targetIPblock := targetNode.IPBlock()
	inSubnetIPblock := nodeInSubnet.IPBlock()
	analyzedConns := na.initConnectivityRelatedCompute(subnet, isIngress)

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := netset.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, err
		}
		if inSubnetIPblock.IsSubset(disjointSubnetCidrIPblock) {
			for resTarget, conn := range analyzedConnsPerCidr.allowedConns {
				if targetIPblock.IsSubset(resTarget) {
					return conn, nil
				}
			}
		}
	}
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, fmt.Errorf(notFoundMsg, isIngress, targetNode.CidrOrAddress(), subnet.cidr, nodeInSubnet.CidrOrAddress())
}

// rulesFilterInConnectivity returns set of rules contributing to a connections given src/dst and direction
// if conn is specified then rules contributing to that connection; otherwise to any connection src->dst
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) rulesFilterInConnectivity(subnet *Subnet,
	nodeInSubnet, targetNode vpcmodel.Node,
	connQuery *connection.Set,
	isIngress bool) (
	allow, deny []int, err error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	targetIPblock := targetNode.IPBlock()
	inSubnetIPblock := nodeInSubnet.IPBlock()
	analyzedConns := na.initConnectivityRelatedCompute(subnet, isIngress)

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := netset.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, nil, err
		}
		if inSubnetIPblock.IsSubset(disjointSubnetCidrIPblock) {
			for resTarget, allowRules := range analyzedConnsPerCidr.allowRules {
				if !targetIPblock.IsSubset(resTarget) {
					continue
				}
				// this is the relevant targetIPblock; takes denyRules as well
				denyRules := analyzedConnsPerCidr.denyRules[resTarget]
				if connQuery == nil {
					return allowRules, denyRules, nil
				}
				var mergedRules []int
				// todo: once we update to go.1.22 use slices.Concat
				mergedRules = append(mergedRules, allowRules...)
				mergedRules = append(mergedRules, denyRules...)
				slices.Sort(mergedRules)
				// connection is part of the query
				// takes only rules relevant to connQuery
				return na.getRulesRelevantConn(mergedRules, connQuery)
			}
		}
	}
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, nil, fmt.Errorf(notFoundMsg, isIngress, targetNode.CidrOrAddress(), subnet.cidr, nodeInSubnet.CidrOrAddress())
}

// given a list of allow and deny rules and a connection,
// return the allow and deny sublists of rules that contributes to the connection
func (na *NACLAnalyzer) getRulesRelevantConn(rules []int,
	connQuery *connection.Set) (allowRelevant, denyRelevant []int, err error) {
	allowRelevant, denyRelevant = []int{}, []int{}
	curConn := connection.None()
	for _, rule := range append(na.ingressRules, na.egressRules...) {
		if !slices.Contains(rules, rule.index) || connQuery.Intersect(rule.connections).IsEmpty() {
			continue
		}
		curConn = curConn.Union(rule.connections)
		if rule.action == ALLOW {
			allowRelevant = append(allowRelevant, rule.index)
		} else if rule.action == DENY {
			denyRelevant = append(denyRelevant, rule.index)
		}
		contains := connQuery.IsSubset(curConn)
		if contains {
			// if the required connQuery is contained in connections thus far, lower priority rules not relevant
			return allowRelevant, denyRelevant, nil
		}
	}
	return allowRelevant, denyRelevant, nil
}

// StringRules returns a string with the details of the specified rules
func (na *NACLAnalyzer) StringRules(rules []int) string {
	strRulesSlice := make([]string, len(rules))
	for i, ruleIndex := range rules {
		strRule, _, _, err := na.getNACLRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRulesSlice[i] = "\t" + strRule
	}
	sort.Strings(strRulesSlice)
	return strings.Join(strRulesSlice, "")
}
