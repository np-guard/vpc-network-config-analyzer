package ibmvpc

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	vpc1 "github.com/IBM/vpc-go-sdk/vpcv1"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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

func (rule *NACLRule) dumpRule() string {
	return fmt.Sprintf("index: %d, src: %s, dst: %s, conn: %s, action: %s",
		rule.index, rule.src.ToIPRanges(), rule.dst.ToIPRanges(), rule.connections.String(), rule.action)
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
func getAllowedXgressConnections(rules []*NACLRule, src, subnetCidr *common.IPBlock,
	disjointPeers []*common.IPBlock, isIngress bool,
) (allowedXgress, deniedXgress map[string]*common.ConnectionSet, allowRules, denyRules map[string][]int) {
	allowedXgress = map[string]*common.ConnectionSet{}
	deniedXgress = map[string]*common.ConnectionSet{}
	allowRules = map[string][]int{}
	denyRules = map[string][]int{}
	for _, cidr := range disjointPeers {
		if cidr.ContainedIn(subnetCidr) {
			allowedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			deniedXgress[cidr.ToIPRanges()] = getEmptyConnSet()
			allowRules[cidr.ToIPRanges()] = []int{}
			denyRules[cidr.ToIPRanges()] = []int{}
		}
	}

	if src.ContainedIn(subnetCidr) {
		// no need to check nacl rules for connections within the subnet
		for _, cidr := range disjointPeers {
			if cidr.ContainedIn(subnetCidr) {
				allowedXgress[cidr.ToIPRanges()] = getAllConnSet()
			}
		}
		return allowedXgress, deniedXgress, allowRules, denyRules
	}

	for _, rule := range rules {
		s, d := rule.getSrcDst(isIngress)
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

func (rule *NACLRule) getSrcDst(isIngress bool) (src, dst *common.IPBlock) {
	if isIngress {
		return rule.src, rule.dst
	}
	return rule.dst, rule.src
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
func AnalyzeNACLRulesPerDisjointTargets(
	rules []*NACLRule, subnet *common.IPBlock, isIngress bool) map[string]*ConnectivityResult {
	res := map[string]*ConnectivityResult{}
	var disjointSrcPeers, disjointDstPeers []*common.IPBlock
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

func updateAllowDeny(allow, isIngress bool, xgressConn map[string]*common.ConnectionSet, rules map[string][]int,
	srcIngDstEgr *common.IPBlock, res map[string]*ConnectivityResult) {
	for dstIngSrcEg, conn := range xgressConn {
		if dstIngSrcEgIPBlock, err := common.IPBlockFromIPRangeStr(dstIngSrcEg); err == nil {
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
			allowedConns: map[*common.IPBlock]*common.ConnectionSet{}, allowRules: map[*common.IPBlock][]int{},
			deniedConns: map[*common.IPBlock]*common.ConnectionSet{}, denyRules: map[*common.IPBlock][]int{}}
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
func (na *NACLAnalyzer) AnalyzeNACLRules(rules []*NACLRule, subnet *common.IPBlock,
	isIngress bool, subnetDisjointTarget *common.IPBlock,
) (string, *ConnectivityResult) {
	res := []string{}
	connResult := &ConnectivityResult{isIngress: isIngress}
	connResult.allowedConns = map[*common.IPBlock]*common.ConnectionSet{}
	connResult.deniedConns = map[*common.IPBlock]*common.ConnectionSet{}
	if subnetDisjointTarget == nil {
		connResult = nil
	}
	if isIngress {
		disjointSrcPeers, disjointDstPeers := getDisjointPeersForIngressAnalysis(rules, subnet)
		// ingress
		for _, src := range disjointSrcPeers {
			allowedIngressConns, _, allowRules, _ := getAllowedXgressConnections(rules, src, subnet, disjointDstPeers, true)
			for dst, conn := range allowedIngressConns {
				res = append(res, getConnStr(src.ToIPRanges(), dst, conn.String()))
				dstIP, err := common.IPBlockFromIPRangeStr(dst)
				if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(dstIP) {
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
			res = append(res, getConnStr(src, dst.ToIPRanges(), conn.String()))
			srcIP, err := common.IPBlockFromIPRangeStr(src)
			if err == nil && subnetDisjointTarget != nil && subnetDisjointTarget.ContainedIn(srcIP) {
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
func (na *NACLAnalyzer) AnalyzeNACL(subnet *common.IPBlock) (
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
	ingressRes, egressRes := na.AnalyzeNACL(subnet.ipblock)
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
func (na *NACLAnalyzer) initConnectivityRelatedCompute(subnet *Subnet, inSubentCidr, target string,
	isIngress bool) (
	analyzedConns map[string]*ConnectivityResult,
	targetIPblock, inSubnetIPblock *common.IPBlock,
	err error) {
	na.addAnalysisPerSubnet(subnet)
	if isIngress {
		analyzedConns = na.analyzedSubnets[subnet.cidr].ingressRes
	} else {
		analyzedConns = na.analyzedSubnets[subnet.cidr].egressRes
	}
	targetIPblock, err1 := common.NewIPBlockFromCidrOrAddress(target)
	inSubnetIPblock, err2 := common.NewIPBlockFromCidrOrAddress(inSubentCidr)
	if err1 != nil && err2 != nil {
		return nil, nil, nil, errors.Join(err1, err2)
	}
	return analyzedConns, targetIPblock, inSubnetIPblock, nil
}

const notFoundMsg = "isIngress: %t , target %s, subnetCidr: %s, inSubentCidr %s, " +
	"could not find connectivity for given target + inSubentCidr"

// AllowedConnectivity returns set of allowed connections given src/dst and direction
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) AllowedConnectivity(subnet *Subnet, inSubentCidr, target string, isIngress bool) (*common.ConnectionSet, error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	analyzedConns, targetIPblock, inSubnetIPblock, err := na.initConnectivityRelatedCompute(subnet, inSubentCidr, target, isIngress)
	if err != nil {
		return nil, err
	}

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := common.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, conn := range analyzedConnsPerCidr.allowedConns {
				if targetIPblock.ContainedIn(resTarget) {
					return conn, nil
				}
			}
		}
	}
	// expecting disjoint ip-blocks, thus not expecting to get here
	return nil, fmt.Errorf(notFoundMsg, isIngress, target, subnet.cidr, inSubentCidr)
}

// rulesFilterInConnectivity returns set of rules contributing to a connections given src/dst and direction
// if conn is specified then rules contributing to that connection; otherwise to any connection src->dst
// if the input subnet was not yet analyzed, it first adds its analysis to saved results
func (na *NACLAnalyzer) rulesFilterInConnectivity(subnet *Subnet, subnetCidr, inSubentCidr,
	target string, connQuery *common.ConnectionSet,
	isIngress bool) (allow, deny []int, err error) {
	// add analysis of the given subnet
	// analyzes per subnet disjoint cidrs (it is not necessarily entire subnet cidr)
	analyzedConns, targetIPblock, inSubnetIPblock, err := na.initConnectivityRelatedCompute(subnet, inSubentCidr, target, isIngress)
	if err != nil {
		return nil, nil, err
	}

	for disjointSubnetCidr, analyzedConnsPerCidr := range analyzedConns {
		disjointSubnetCidrIPblock, err := common.IPBlockFromIPRangeStr(disjointSubnetCidr)
		if err != nil {
			return nil, nil, err
		}
		if inSubnetIPblock.ContainedIn(disjointSubnetCidrIPblock) {
			for resTarget, allowRules := range analyzedConnsPerCidr.allowRules {
				if !targetIPblock.ContainedIn(resTarget) {
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
	return nil, nil, fmt.Errorf(notFoundMsg, isIngress, target, subnetCidr, inSubentCidr)
}

// given a list of allow and deny rules and a connection,
// return the allow and deny sublists of rules that contributes to the connection
func (na *NACLAnalyzer) getRulesRelevantConn(rules []int,
	connQuery *common.ConnectionSet) (allowRelevant, denyRelevant []int, err error) {
	allowRelevant, denyRelevant = []int{}, []int{}
	curConn := common.NewConnectionSet(false)
	for _, rule := range append(na.ingressRules, na.egressRules...) {
		if !slices.Contains(rules, rule.index) || connQuery.Intersection(rule.connections).IsEmpty() {
			continue
		}
		curConn = curConn.Union(rule.connections)
		if rule.action == ALLOW {
			allowRelevant = append(allowRelevant, rule.index)
		} else if rule.action == DENY {
			denyRelevant = append(denyRelevant, rule.index)
		}
		contains, err := connQuery.ContainedIn(curConn)
		if err != nil {
			return nil, nil, err
		}
		if contains {
			// if the required connQuery is contained in connections thus far, lower priority rules not relevant
			return allowRelevant, denyRelevant, nil
		}
	}
	return allowRelevant, denyRelevant, nil
}

// StringRules returns a string with the details of the specified rules
func (na *NACLAnalyzer) StringRules(rules []int) string {
	var strRules string
	for _, ruleIndex := range rules {
		if ruleIndex == vpcmodel.DummyRule {
			continue
		}
		strRule, _, _, err := na.getNACLRule(ruleIndex)
		if err != nil {
			return ""
		}
		strRules += "\t" + strRule
	}
	return strRules
}
