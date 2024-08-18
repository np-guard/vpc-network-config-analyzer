/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package commonvpc

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const (
	ALLOW string = "allow"
	DENY  string = "deny"
)

// NACLAnalyzer captures common nacl properties for aws and ibm: rules and AnalyzedSubnets
type NACLAnalyzer struct {
	NaclAnalyzer SpecificNACLAnalyzer
	IngressRules []*NACLRule
	EgressRules  []*NACLRule
	// analysis results
	AnalyzedSubnets map[string]*AnalysisResultPerSubnet
}

// interface to be implemented by aws and ibm nacl analyzer
type SpecificNACLAnalyzer interface {
	GetNACLRules() (ingressRules, egressRules []*NACLRule, err error)
	ReferencedIPblocks() []*ipblock.IPBlock
	GetNumberOfRules() int
	GetNACLRule(index int) (ruleStr string, ruleRes *NACLRule, isIngress bool, err error)
	Name() *string
}

type AnalysisResultPerSubnet struct {
	subnet     string
	ingressRes map[string]*ConnectivityResult // map from disjoint-subnet-cidr to its analysis res (ingress)
	egressRes  map[string]*ConnectivityResult // map from disjoint-subnet-cidr  its analysis res (egress)
	// todo: add ingress and egress explicitly denied
}

func NewAnalysisResultPerSubnet(subnet string, ingressRes,
	egressRes map[string]*ConnectivityResult) (res *AnalysisResultPerSubnet) {
	return &AnalysisResultPerSubnet{subnet: subnet, ingressRes: ingressRes, egressRes: egressRes}
}

func NewNACLAnalyzer(analyzer SpecificNACLAnalyzer) (res *NACLAnalyzer, err error) {
	res = &NACLAnalyzer{
		NaclAnalyzer:    analyzer,
		AnalyzedSubnets: map[string]*AnalysisResultPerSubnet{},
	}
	res.IngressRules, res.EgressRules, err = res.NaclAnalyzer.GetNACLRules()
	return res, err
}

// NACLRule represents an nacl rule, used in ibm and aws
type NACLRule struct {
	Src         *ipblock.IPBlock
	Dst         *ipblock.IPBlock
	Connections *connection.Set
	Action      string
	Index       int // index of original rule in it's NetworkACL
	// add ingress/egress ?
}

func (rule *NACLRule) dumpRule() string {
	return fmt.Sprintf("index: %d, src: %s, dst: %s, conn: %s, action: %s",
		rule.Index, rule.Src.ToIPRanges(), rule.Dst.ToIPRanges(), rule.Connections.String(), rule.Action)
}

var _ = (*NACLAnalyzer).dumpNACLrules // avoiding "unused" warning

func (na *NACLAnalyzer) dumpNACLrules() string {
	res := "ingress rules:\n"
	ingressList := []string{}
	for _, r := range na.IngressRules {
		ingressList = append(ingressList, r.dumpRule())
	}
	egressList := []string{}
	for _, r := range na.EgressRules {
		egressList = append(egressList, r.dumpRule())
	}
	res += strings.Join(ingressList, "\n")
	res += "\negress rules:\n"
	res += strings.Join(egressList, "\n")
	return res
}

// given ingress/egress rules from NACL , specific src, subnet cidr and disjoint peers of dest ip-blocks --
// get the allowed connections, the relevant allow rules and relevant deny rules
func GetAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *ipblock.IPBlock,
	disjointPeers []*ipblock.IPBlock, isIngress bool,
) (allowedXgress, deniedXgress map[string]*connection.Set, allowRules, denyRules map[string][]int) {
	allowedXgress = map[string]*connection.Set{}
	deniedXgress = map[string]*connection.Set{}
	allowRules = map[string][]int{}
	denyRules = map[string][]int{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedXgress[cidr.ToIPRanges()] = connection.None()
			deniedXgress[cidr.ToIPRanges()] = connection.None()
			allowRules[cidr.ToIPRanges()] = []int{}
			denyRules[cidr.ToIPRanges()] = []int{}
		}
	}

	if src.ContainedIn(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				allowedXgress[cidr.ToIPRanges()] = connection.All()
			}
		}
		return allowedXgress, deniedXgress, allowRules, denyRules
	}

	for _, rule := range rules {
		s, d := rule.getSrcDst(isIngress)
		if !src.ContainedIn(s) {
			continue
		}
		destCidr := d.Intersect(subnetCidr)
		// split destCidr to disjoint ip-blocks
		destCidrList := []*ipblock.IPBlock{}
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(destCidr) {
				destCidrList = append(destCidrList, cidr)
			}
		}
		for _, disjointDestCidr := range destCidrList {
			disjointDestIP := disjointDestCidr.ToIPRanges()
			if rule.Action == ALLOW {
				addedAllowedConns := rule.Connections.Copy()
				addedAllowedConns = addedAllowedConns.Subtract(deniedXgress[disjointDestIP])
				// issue here at union below
				allowedXgressDestCidrBefore := allowedXgress[disjointDestIP]
				allowedXgress[disjointDestIP] = allowedXgress[disjointDestIP].Union(addedAllowedConns)
				if !allowedXgress[disjointDestIP].Equal(allowedXgressDestCidrBefore) { // this rule contributes to the connection
					allowRules[disjointDestIP] = append(allowRules[disjointDestIP], rule.Index)
				}
			} else if rule.Action == DENY {
				addedDeniedConns := rule.Connections.Copy()
				addedDeniedConns = addedDeniedConns.Subtract(allowedXgress[disjointDestIP])
				deniedXgressDestCidrBefore := deniedXgress[disjointDestIP]
				deniedXgress[disjointDestIP] = deniedXgress[disjointDestIP].Union(addedDeniedConns)
				if !deniedXgress[disjointDestIP].Equal(deniedXgressDestCidrBefore) { // this deny rule is relevant to the connection
					denyRules[disjointDestIP] = append(denyRules[disjointDestIP], rule.Index)
				}
			}
		}
	}
	return allowedXgress, deniedXgress, allowRules, denyRules
}

func (rule *NACLRule) getSrcDst(isIngress bool) (src, dst *ipblock.IPBlock) {
	if isIngress {
		return rule.Src, rule.Dst
	}
	return rule.Dst, rule.Src
}

func getDisjointPeersForIngressOrEgressAnalysis(
	rules []*NACLRule, subnet *ipblock.IPBlock, isIngress bool) (
	disjointSrcPeers,
	disjointDstPeers []*ipblock.IPBlock) {
	var srcPeers, dstPeers []*ipblock.IPBlock
	srcPeers = make([]*ipblock.IPBlock, 1+len(rules))
	dstPeers = make([]*ipblock.IPBlock, 1+len(rules))
	cidrAll := ipblock.GetCidrAll()
	if isIngress {
		srcPeers[0] = cidrAll
		dstPeers[0] = subnet
	} else {
		srcPeers[0] = subnet
		dstPeers[0] = cidrAll
	}
	for i, rule := range rules {
		srcPeers[i+1] = rule.Src
		dstPeers[i+1] = rule.Dst
	}
	if isIngress {
		disjointSrcPeers = ipblock.DisjointIPBlocks(srcPeers, []*ipblock.IPBlock{ipblock.GetCidrAll()})
		disjointDstPeers = ipblock.DisjointIPBlocks(dstPeers, []*ipblock.IPBlock{subnet})
	} else {
		disjointSrcPeers = ipblock.DisjointIPBlocks(srcPeers, []*ipblock.IPBlock{subnet})
		disjointDstPeers = ipblock.DisjointIPBlocks(dstPeers, []*ipblock.IPBlock{ipblock.GetCidrAll()})
	}
	return
}

func getDisjointPeersForIngressAnalysis(rules []*NACLRule, subnet *ipblock.IPBlock) (srcPeers, dstPeers []*ipblock.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, true)
}

func getDisjointPeersForEgressAnalysis(rules []*NACLRule, subnet *ipblock.IPBlock) (srcPeers, dstPeers []*ipblock.IPBlock) {
	return getDisjointPeersForIngressOrEgressAnalysis(rules, subnet, false)
}

// AnalyzeNACLRulesPerDisjointTargets get connectivity result for each disjoint target in the subnet
func AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *ipblock.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	var disjointSrcPeers, disjointDstPeers []*ipblock.IPBlock
	if isIngress {
		disjointSrcPeers, disjointDstPeers = getDisjointPeersForIngressAnalysis(rules, subnet)
	} else {
		disjointDstPeers, disjointSrcPeers = getDisjointPeersForEgressAnalysis(rules, subnet)
	}
	for _, srcIngDstEgr := range disjointSrcPeers {
		allowedIngressConns, deniedIngressConns,
			allowRules, denyRules := GetAllowedXgressConnections(rules, srcIngDstEgr, subnet, disjointDstPeers, isIngress)
		updateAllowDeny(true, isIngress, allowedIngressConns, allowRules, srcIngDstEgr, res)
		updateAllowDeny(false, isIngress, deniedIngressConns, denyRules, srcIngDstEgr, res)
	}
	return res
}

func updateAllowDeny(allow, isIngress bool, xgressConn map[string]*connection.Set, rules map[string][]int,
	srcIngDstEgr *ipblock.IPBlock, res map[string]*ConnectivityResult) {
	for dstIngSrcEg, conn := range xgressConn {
		if dstIngSrcEgIPBlock, err := ipblock.FromIPRangeStr(dstIngSrcEg); err == nil {
			dstIngSrcEgIPRange := dstIngSrcEgIPBlock.ToIPRanges()
			initConnectivityResult(res, dstIngSrcEgIPRange, isIngress)
			if allow {
				res[dstIngSrcEgIPRange].AllowedConns[srcIngDstEgr] = conn
				// allowRules indexes are identical to these of allowedIngressConns, thus access legit
				res[dstIngSrcEgIPRange].AllowRules[srcIngDstEgr] = rules[dstIngSrcEg]
			} else {
				res[dstIngSrcEgIPRange].DeniedConns[srcIngDstEgr] = conn
				// allowRules indexes are identical to these of allowedIngressConns, thus access legit
				res[dstIngSrcEgIPRange].DenyRules[srcIngDstEgr] = rules[dstIngSrcEg]
			}
		}
	}
}

func initConnectivityResult(connectivityMap map[string]*ConnectivityResult, indxToinit string, isIngress bool) {
	if _, ok := connectivityMap[indxToinit]; !ok {
		connectivityMap[indxToinit] = &ConnectivityResult{IsIngress: isIngress,
			AllowedConns: map[*ipblock.IPBlock]*connection.Set{}, AllowRules: map[*ipblock.IPBlock][]int{},
			DeniedConns: map[*ipblock.IPBlock]*connection.Set{}, DenyRules: map[*ipblock.IPBlock][]int{}}
	}
}

func getConnStr(src, dst, conn string) string {
	return fmt.Sprintf("%s => %s : %s\n", src, dst, conn)
}

// AnalyzeNACLRules todo: this is used only in testing. Did not expand for deny.
func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *ipblock.IPBlock,
	isIngress bool, subnetDisjointTarget *ipblock.IPBlock,
) (string, *ConnectivityResult) {
	res := []string{}
	connResult := &ConnectivityResult{IsIngress: isIngress}
	connResult.AllowedConns = map[*ipblock.IPBlock]*connection.Set{}
	connResult.DeniedConns = map[*ipblock.IPBlock]*connection.Set{}
	if subnetDisjointTarget == nil {
		connResult = nil
	}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns, _, allowRules, _ := GetAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, getConnStr(src.ToIPRanges(), dst, conn.String()))
				dstIP, err := ipblock.FromIPRangeStr(dst)
				if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(dstIP) {
					connResult.AllowedConns[src] = conn
					// the indexing of allowedIngressConns and allowRules are identical
					connResult.AllowRules[src] = allowRules[dst]
				}
			}
		}
		return strings.Join(res, ""), connResult
	}
	// egress
	disjointSrcPeers, disjointDstPeers := getDisjointPeersForEgressAnalysis(rules, subnet)
	for _, dst := range disjointDstPeers {
		allowedEgressConns, _, allowRules, _ := GetAllowedXgressConnections(rules, dst, subnet, disjointSrcPeers, false)
		for src, conn := range allowedEgressConns {
			res = append(res, getConnStr(src, dst.ToIPRanges(), conn.String()))
			srcIP, err := ipblock.FromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(srcIP) {
				connResult.AllowedConns[dst] = conn
				// the indexing of allowedEgressConns and allowRules are identical
				connResult.AllowRules[dst] = allowRules[src]
			}
		}
	}
	return strings.Join(res, ""), connResult
}

// TODO: return a map from each possible subnetDisjointTarget to its ConnectivityResult, instead of a specific ConnectivityResult
// get allowed and denied connections (ingress and egress) for a certain subnet to which this nacl is applied
func (na *NACLAnalyzer) AnalyzeNACL(subnet *ipblock.IPBlock) (
	ingressResConnectivity, egressResConnectivity map[string]*ConnectivityResult) {
	ingressResConnectivity = AnalyzeNACLRulesPerDisjointTargets(na.IngressRules, subnet, true)
	egressResConnectivity = AnalyzeNACLRulesPerDisjointTargets(na.EgressRules, subnet, false)
	return ingressResConnectivity, egressResConnectivity
}

// this function adds the analysis of certain subnet connectivity based on the the NACL
// it saves the analysis results in na.analyzedSubnets
func (na *NACLAnalyzer) AddAnalysisPerSubnet(subnet *Subnet) {
	if _, ok := na.AnalyzedSubnets[subnet.Cidr]; ok {
		return
	}
	ingressRes, egressRes := na.AnalyzeNACL(subnet.IPblock)
	na.AnalyzedSubnets[subnet.Cidr] = NewAnalysisResultPerSubnet(subnet.Cidr, ingressRes, egressRes)
}

// GeneralConnectivityPerSubnet returns the str of the connectivity for analyzed subnet input
func (na *NACLAnalyzer) GeneralConnectivityPerSubnet(subnet *Subnet) (
	strResult string,
	connectivityObjResult map[string]*vpcmodel.IPbasedConnectivityResult,
) {
	na.AddAnalysisPerSubnet(subnet)

	strResult = "Subnet: " + subnet.Cidr + "\n"
	ingressRes := na.AnalyzedSubnets[subnet.Cidr].ingressRes
	egressRes := na.AnalyzedSubnets[subnet.Cidr].egressRes
	connectivityObjResult = map[string]*vpcmodel.IPbasedConnectivityResult{}

	// map from disjointSubnetCidr to its connectivity str
	strResPerSubnetSection := map[string]string{}

	for disjointSubnetCidr, connectivityRes := range ingressRes {
		// assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		// TODO: currently assuming assignment here only once due to single subnet connectivity result (no partial subnet res)
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].IngressAllowedConns = connectivityRes.AllowedConns
		strResPerSubnetSection[disjointSubnetCidr] = "Ingress Connectivity:\n" + connectivityRes.String()
	}

	for disjointSubnetCidr, connectivityRes := range egressRes {
		if _, ok := connectivityObjResult[disjointSubnetCidr]; !ok {
			connectivityObjResult[disjointSubnetCidr] = &vpcmodel.IPbasedConnectivityResult{}
		}
		connectivityObjResult[disjointSubnetCidr].EgressAllowedConns = connectivityRes.AllowedConns
		strResPerSubnetSection[disjointSubnetCidr] += "\nEgress Connectivity:\n" + connectivityRes.String()
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
	na.AddAnalysisPerSubnet(subnet)
	if isIngress {
		analyzedConns = na.AnalyzedSubnets[subnet.Cidr].ingressRes
	} else {
		analyzedConns = na.AnalyzedSubnets[subnet.Cidr].egressRes
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
		disjointSubnetCidrIPblock, err := ipblock.FromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, conn := range analyzedConnsPerCidr.AllowedConns {
				if targetIPblock.ContainedIn(resTarget) {
					return conn, nil
				}
			}
		}
	}
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, fmt.Errorf(notFoundMsg, isIngress, targetNode.CidrOrAddress(), subnet.Cidr, nodeInSubnet.CidrOrAddress())
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
		disjointSubnetCidrIPblock, err := ipblock.FromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, allowRules := range analyzedConnsPerCidr.AllowRules {
				if !targetIPblock.ContainedIn(resTarget) {
					continue
				}
				// this is the relevant targetIPblock; takes denyRules as well
				denyRules := analyzedConnsPerCidr.DenyRules[resTarget]
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
	return nil, nil, fmt.Errorf(notFoundMsg, isIngress, targetNode.CidrOrAddress(), subnet.Cidr, nodeInSubnet.CidrOrAddress())
}

// given a list of allow and deny rules and a connection,
// return the allow and deny sublists of rules that contributes to the connection
func (na *NACLAnalyzer) getRulesRelevantConn(rules []int,
	connQuery *connection.Set) (allowRelevant, denyRelevant []int, err error) {
	allowRelevant, denyRelevant = []int{}, []int{}
	curConn := connection.None()
	for _, rule := range append(na.IngressRules, na.EgressRules...) {
		if !slices.Contains(rules, rule.Index) || connQuery.Intersect(rule.Connections).IsEmpty() {
			continue
		}
		curConn = curConn.Union(rule.Connections)
		if rule.Action == ALLOW {
			allowRelevant = append(allowRelevant, rule.Index)
		} else if rule.Action == DENY {
			denyRelevant = append(denyRelevant, rule.Index)
		}
		contains := connQuery.ContainedIn(curConn)
		if contains {
			// if the required connQuery is contained in connections thus far, lower priority rules not relevant
			return allowRelevant, denyRelevant, nil
		}
	}
	return allowRelevant, denyRelevant, nil
}

// GetNACLRules returns ingress and egress rule objects
func GetNACLRules(numRules int, na SpecificNACLAnalyzer) (ingressRules,
	egressRules []*NACLRule, referencedIPblocks []*ipblock.IPBlock, err error) {
	ingressRules = []*NACLRule{}
	egressRules = []*NACLRule{}
	for index := 0; index < numRules; index++ {
		_, ruleObj, isIngress, err := na.GetNACLRule(index)
		if err != nil {
			return nil, nil, nil, err
		}
		if ruleObj == nil {
			continue
		}
		referencedIPblocks = append(referencedIPblocks, ruleObj.Src.Split()...)
		referencedIPblocks = append(referencedIPblocks, ruleObj.Dst.Split()...)
		ruleObj.Index = index
		if isIngress {
			ingressRules = append(ingressRules, ruleObj)
		} else {
			egressRules = append(egressRules, ruleObj)
		}
	}
	return ingressRules, egressRules, referencedIPblocks, nil
}
