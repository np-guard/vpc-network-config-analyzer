package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

const commaSeparator = ","

// for each line here can group list of external nodes to cidrs list as of one element
// groupedNodesInfo contains the list of nodes to be grouped and their common connection properties
type groupingConnections map[EndpointElem]map[string]*groupedExternalNodesInfo

type groupedExternalNodesInfo struct {
	nodes            groupedExternalNodes
	commonProperties *groupedCommonProperties
}

type explainDetails struct {
	rules           *rulesConnection
	router          RoutingResource
	filtersRelevant map[string]bool
	connEnabled     bool
	ingressEnabled  bool
	egressEnabled   bool
}

type groupedCommonProperties struct {
	conn       *connection.Set
	connDiff   *connectionDiff
	expDetails *explainDetails
	// groupingStrKey is the key by which the grouping is done:
	// the string of conn per grouping of conn lines, string of connDiff per grouping of diff lines
	// and string of conn and explainDetails for explainblity
	groupingStrKey string // the key used for grouping per connectivity lines or diff lines
}

func (g *groupedExternalNodesInfo) appendNode(n *ExternalNetwork) {
	g.nodes = append(g.nodes, n)
}

func (g *groupingConnections) getGroupedConnLines(groupedConnLines *GroupConnLines,
	isSrcToDst bool) []*groupedConnLine {
	res := []*groupedConnLine{}
	for a, aMap := range *g {
		for _, b := range aMap {
			var resElem *groupedConnLine
			bGrouped := groupedConnLines.cacheGrouped.getAndSetGroupedExternalFromCache(&b.nodes)
			if isSrcToDst {
				resElem = &groupedConnLine{a, bGrouped, b.commonProperties}
			} else {
				resElem = &groupedConnLine{bGrouped, a, b.commonProperties}
			}
			res = append(res, resElem)
		}
	}
	return res
}

func newGroupingConnections() *groupingConnections {
	res := groupingConnections(map[EndpointElem]map[string]*groupedExternalNodesInfo{})
	return &res
}

func newGroupConnLines(c *VPCConfig, v *VPCConnectivity,
	grouping bool) (res *GroupConnLines, err error) {
	res = &GroupConnLines{config: c, nodesConn: v,
		srcToDst:     newGroupingConnections(),
		dstToSrc:     newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err = res.computeGrouping(true, grouping)
	return res, err
}

func newGroupConnLinesSubnetConnectivity(c *VPCConfig, s *VPCsubnetConnectivity,
	grouping bool) (res *GroupConnLines, err error) {
	res = &GroupConnLines{config: c, subnetsConn: s,
		srcToDst:     newGroupingConnections(),
		dstToSrc:     newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err = res.computeGrouping(false, grouping)
	return res, err
}

func newGroupConnLinesDiff(d *diffBetweenCfgs) (res *GroupConnLines, err error) {
	res = &GroupConnLines{diff: d,
		srcToDst:     newGroupingConnections(),
		dstToSrc:     newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err = res.computeGroupingForDiff()
	return res, err
}

func newGroupConnExplainability(c *VPCConfig, e *rulesAndConnDetails) (res *GroupConnLines, err error) {
	res = &GroupConnLines{
		config:       c,
		explain:      e,
		srcToDst:     newGroupingConnections(),
		dstToSrc:     newGroupingConnections(),
		cacheGrouped: newCacheGroupedElements()}
	err = res.groupExternalAddressesForExplainability()
	return res, err
}

// GroupConnLines used both for VPCConnectivity and for VPCsubnetConnectivity, one at a time. The other must be nil
// todo: define abstraction above both?
type GroupConnLines struct {
	config      *VPCConfig
	nodesConn   *VPCConnectivity
	subnetsConn *VPCsubnetConnectivity
	diff        *diffBetweenCfgs
	explain     *rulesAndConnDetails
	srcToDst    *groupingConnections
	dstToSrc    *groupingConnections
	// cache with two maps: 1. from unified key to groupedEndpointsElems
	// 2. from unified key to groupedExternalNodes
	// the item in the maps represents grouped vsis/subnets/external elements
	// the cache is used to avoid duplication of identical groupedEndpointsElems
	cacheGrouped *cacheGroupedElements
	GroupedLines []*groupedConnLine
}

// EndpointElem can be Node(networkInterface) / groupedExternalNodes / groupedNetworkInterfaces / NodeSet(subnet)
type EndpointElem interface {
	Name() string
	IsExternal() bool
	DrawioResourceIntf
}

type groupedConnLine struct {
	src              EndpointElem
	dst              EndpointElem
	commonProperties *groupedCommonProperties // holds the common conn/diff properties
}

func (g *groupedConnLine) String() string {
	return g.src.Name() + " => " + g.dst.Name() + " : " + g.commonProperties.groupingStrKey
}

func (g *groupedConnLine) ConnLabel() string {
	if g.commonProperties.conn.IsAll() {
		return ""
	}
	return g.commonProperties.groupingStrKey
}

func (g *groupedConnLine) getSrcOrDst(isSrc bool) EndpointElem {
	if isSrc {
		return g.src
	}
	return g.dst
}

type groupedEndpointsElems []EndpointElem

func (g *groupedEndpointsElems) Name() string {
	return listEndpointElemStr(*g, EndpointElem.Name)
}

func (g *groupedEndpointsElems) IsExternal() bool {
	return false
}

// implements endpointElem interface
type groupedExternalNodes []*ExternalNetwork

func (g *groupedExternalNodes) IsExternal() bool {
	return true
}

func (g *groupedExternalNodes) Name() string {
	isAllInternetRange, err := isEntirePublicInternetRange(*g)
	prefix := publicInternetNodeName + " "
	if err == nil && isAllInternetRange {
		return prefix + "(all ranges)"
	}
	return prefix + g.String()
}

func (g *groupingConnections) addPublicConnectivity(ep EndpointElem, commonProps *groupedCommonProperties, targetNode *ExternalNetwork) {
	connKey := commonProps.groupingStrKey
	if _, ok := (*g)[ep]; !ok {
		(*g)[ep] = map[string]*groupedExternalNodesInfo{}
	}
	if _, ok := (*g)[ep][connKey]; !ok {
		(*g)[ep][connKey] = &groupedExternalNodesInfo{commonProperties: commonProps}
	}
	(*g)[ep][connKey].appendNode(targetNode)
}

// given an endpoint representing a VSI or a subnet
// returns the UID of the vsi's subnet in the former case or of
// the subnet's VPC is the latter.
func getSubnetOrVPCUID(ep EndpointElem) string {
	UID := getSubnetUIDIfVsi(ep)
	if UID == "" {
		UID = getVPCUIDIfSubnet(ep)
	}
	return UID
}

// group public internet ranges for vsis/subnets connectivity lines
func (g *GroupConnLines) groupExternalAddresses(vsi bool) error {
	var allowedConnsCombined GeneralConnectivityMap
	if vsi {
		allowedConnsCombined = g.nodesConn.AllowedConnsCombined
	} else {
		allowedConnsCombined = g.subnetsConn.AllowedConnsCombined
	}
	res := []*groupedConnLine{}
	for src, nodeConns := range allowedConnsCombined {
		for dst, conns := range nodeConns {
			if !conns.IsEmpty() {
				err := g.addLineToExternalGrouping(&res, src, dst,
					&groupedCommonProperties{conn: conns, groupingStrKey: conns.EnhancedString()})
				if err != nil {
					return err
				}
			}
		}
	}
	g.appendGrouped(res)
	return nil
}

// group public internet ranges for semantic-diff connectivity lines (subnets/vsis)
func (g *GroupConnLines) groupExternalAddressesForDiff(thisMinusOther bool) error {
	// initialize data structures; this is required for the 2nd call of this function
	g.srcToDst = newGroupingConnections()
	g.dstToSrc = newGroupingConnections()
	var res []*groupedConnLine
	var connRemovedChanged connectivityDiff
	if thisMinusOther {
		connRemovedChanged = g.diff.cfg1ConnRemovedFrom2
	} else {
		connRemovedChanged = g.diff.cfg2ConnRemovedFrom1
	}
	for src, endpointConnDiff := range connRemovedChanged {
		for dst, connDiff := range endpointConnDiff {
			connDiffString := connDiffEncode(src, dst, connDiff)
			if !(connDiff.conn1.IsEmpty() && connDiff.conn2.IsEmpty()) {
				err := g.addLineToExternalGrouping(&res, src, dst,
					&groupedCommonProperties{connDiff: connDiff, groupingStrKey: connDiffString})
				if err != nil {
					return err
				}
			}
		}
	}
	g.appendGrouped(res)
	return nil
}

// group public internet ranges for explainability lines
func (g *GroupConnLines) groupExternalAddressesForExplainability() error {
	var res []*groupedConnLine
	for _, details := range *g.explain {
		groupingStrKey := details.explanationEncode(g.config)
		expDetails := &explainDetails{details.actualMergedRules, details.router, details.filtersRelevant,
			details.connEnabled, details.ingressEnabled, details.egressEnabled}
		err := g.addLineToExternalGrouping(&res, details.src, details.dst,
			&groupedCommonProperties{conn: details.conn, expDetails: expDetails,
				groupingStrKey: groupingStrKey})
		if err != nil {
			return err
		}
	}
	g.appendGrouped(res)
	return nil
}

func (g *GroupConnLines) addLineToExternalGrouping(res *[]*groupedConnLine,
	src, dst VPCResourceIntf, commonProps *groupedCommonProperties) error {
	srcNode, srcIsNode := src.(Node)
	dstNode, dstIsNode := dst.(Node)
	if dst.IsExternal() && !dstIsNode ||
		src.IsExternal() && !srcIsNode {
		return fmt.Errorf("%s or %s is External but not a node", src.Name(), dst.Name())
	}
	if dst.IsExternal() && src.IsExternal() {
		return fmt.Errorf("unexpected grouping - both src and dst external")
	}
	switch {
	case dst.IsExternal():
		g.srcToDst.addPublicConnectivity(src, commonProps, dstNode.(*ExternalNetwork))
	case src.IsExternal():
		g.dstToSrc.addPublicConnectivity(dst, commonProps, srcNode.(*ExternalNetwork))
	default:
		*res = append(*res, &groupedConnLine{src, dst, commonProps})
	}
	return nil
}

// add to res lines from  srcToDst and DstToSrc groupings
func (g *GroupConnLines) appendGrouped(res []*groupedConnLine) {
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(g, true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(g, false)...)
	g.GroupedLines = append(g.GroupedLines, res...)
}

// aux func, returns true iff the EndpointElem is Node if grouping vsis or NodeSet if grouping subnets
func isInternalOfRequiredType(ep EndpointElem, groupVsi bool) bool {
	if groupVsi { // groups vsis Nodes
		if _, ok := ep.(InternalNodeIntf); !ok {
			return false
		}
	} else { // groups subnets NodeSets
		if _, ok := ep.(Subnet); !ok {
			return false
		}
	}
	return true
}

// groups src/targets for either Vsis or Subnets
func (g *GroupConnLines) groupLinesByKey(srcGrouping, groupVsi bool) (res []*groupedConnLine,
	groupingSrcOrDst map[string][]*groupedConnLine) {
	res = []*groupedConnLine{}
	// build map from str(dst+conn) to []src => create lines accordingly
	groupingSrcOrDst = map[string][]*groupedConnLine{}
	// populate map groupingSrcOrDst
	for _, line := range g.GroupedLines {
		grpTarget, grpIndex := line.getSrcOrDst(srcGrouping), line.getSrcOrDst(!srcGrouping)
		if !isInternalOfRequiredType(grpTarget, groupVsi) {
			res = append(res, line)
			continue
		}
		key := getKeyOfGroupConnLines(grpIndex, grpTarget, line.commonProperties.groupingStrKey)
		if _, ok := groupingSrcOrDst[key]; !ok {
			groupingSrcOrDst[key] = []*groupedConnLine{}
		}
		groupingSrcOrDst[key] = append(groupingSrcOrDst[key], line)
	}
	newGroupingSrcOrDst := g.extendGroupingSelfLoops(groupingSrcOrDst, srcGrouping)

	return res, newGroupingSrcOrDst
}

// grouping by:
// 1. Name of indexed endpoint (see #412) and its connection
// 2. We do not want to group together vsis from different subnets for vsis analyais
// or subnets of different vpcs for subnets analysis; thus the grouping is also by subnets/vpcs
// of grouping targets
// e.g. :
// v2 => v3
// v2 => v3
// can be grouped to
// v1, v2 => v3 given that v1, v2 share the same subnet
func getKeyOfGroupConnLines(grpIndex, grpTarget EndpointElem, connectionString string) string {
	keyComponents := []string{grpIndex.Name(), connectionString, getSubnetOrVPCUID(grpTarget)}
	return strings.Join(keyComponents, semicolon)
}

// assuming the  g.groupedLines was already initialized by previous step groupExternalAddresses()
func (g *GroupConnLines) groupInternalSrcOrDst(srcGrouping, groupVsi bool) {
	res, groupingSrcOrDst := g.groupLinesByKey(srcGrouping, groupVsi)

	// actual grouping vsis/subnets to be grouped
	for _, linesGroup := range groupingSrcOrDst {
		nodesList := make([]EndpointElem, len(linesGroup))
		for i, line := range linesGroup {
			nodesList[i] = line.getSrcOrDst(srcGrouping)
		}
		groupedEndpoints := groupedEndpointsElems(nodesList)
		groupedNodes := g.cacheGrouped.getAndSetEndpointElemFromCache(&groupedEndpoints)
		if srcGrouping {
			res = append(res, &groupedConnLine{groupedNodes, linesGroup[0].dst, linesGroup[0].commonProperties})
		} else {
			res = append(res, &groupedConnLine{linesGroup[0].src, groupedNodes, linesGroup[0].commonProperties})
		}
	}
	g.GroupedLines = unifiedGroupedConnLines(res, g.cacheGrouped, false)
}

// Go over the grouping result and set groups s.t. all semantically equiv groups have a unified reference.
// this is required for multivpc's context and at the end of the grouping in a single vpc context
// the former is required since each vpc analysis and grouping is done separately
// the latter is required due to the functionality treating self loops as don't cares - extendGroupingSelfLoops
// in which both srcs and dsts are manipulated  but *GroupConnLines is not familiar
// within the extendGroupingSelfLoops context and thus can not be done there smoothly
func unifiedGroupedConnLines(oldConnLines []*groupedConnLine, cacheGrouped *cacheGroupedElements,
	unifyGroupedExternalNodes bool) []*groupedConnLine {
	newGroupedLines := make([]*groupedConnLine, len(oldConnLines))
	// go over all connections; if src/dst is not external then use groupedEndpointsElemsMap
	for i, groupedLine := range oldConnLines {
		newGroupedLines[i] = &groupedConnLine{unifiedGroupedElems(groupedLine.src, cacheGrouped, unifyGroupedExternalNodes),
			unifiedGroupedElems(groupedLine.dst, cacheGrouped, unifyGroupedExternalNodes),
			groupedLine.commonProperties}
	}
	return newGroupedLines
}

// unifies reference to a single element
func unifiedGroupedElems(srcOrDst EndpointElem,
	cachedGrouped *cacheGroupedElements,
	unifyGroupedExternalNodes bool) EndpointElem {
	// external in case external grouping does not need to be unifed
	if !unifyGroupedExternalNodes && srcOrDst.IsExternal() {
		return srcOrDst
	}
	if _, ok := srcOrDst.(InternalNodeIntf); ok { // single vsi or single external node
		return srcOrDst
	}
	if _, ok := srcOrDst.(Subnet); ok { // subnet
		return srcOrDst
	}
	if groupedEE, ok := srcOrDst.(*groupedEndpointsElems); ok {
		unifiedGroupedEE := cachedGrouped.getAndSetEndpointElemFromCache(groupedEE)
		return unifiedGroupedEE
	}
	if groupedExternal, ok := srcOrDst.(*groupedExternalNodes); ok {
		unifiedGroupedEE := cachedGrouped.getAndSetGroupedExternalFromCache(groupedExternal)
		return unifiedGroupedEE
	}
	return srcOrDst
}

// computeGrouping does the grouping; for vsis (all_endpoints analysis)
// if vsi = true otherwise for subnets (all_subnets analysis)
// external endpoints are always grouped; vsis/subnets are grouped iff grouping is true
func (g *GroupConnLines) computeGrouping(vsi, grouping bool) (err error) {
	err = g.groupExternalAddresses(vsi)
	if err != nil {
		return err
	}
	if grouping {
		g.groupInternalSrcOrDst(true, vsi)
		g.groupInternalSrcOrDst(false, vsi)
	}
	return nil
}

func (g *GroupConnLines) computeGroupingForDiff() error {
	err := g.groupExternalAddressesForDiff(true)
	if err != nil {
		return err
	}
	err = g.groupExternalAddressesForDiff(false)
	return err
}

// get the grouped connectivity output
func (g *GroupConnLines) String() string {
	if len(g.GroupedLines) == 0 {
		return "<nothing to report>\n"
	}
	linesStr := make([]string, len(g.GroupedLines))
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + "\n"
}

// get indication if the connections contain a stateless connection
func (g *GroupConnLines) hasStatelessConns() bool {
	hasStatelessConns := false
	for _, line := range g.GroupedLines {
		if line.commonProperties.conn.IsStateful == connection.StatefulFalse {
			hasStatelessConns = true
			break
		}
	}
	return hasStatelessConns
}

func listEndpointElemStr(eps []EndpointElem, fn func(ep EndpointElem) string) string {
	endpointsStrings := make([]string, len(eps))
	for i, ep := range eps {
		endpointsStrings[i] = fn(ep)
	}
	sort.Strings(endpointsStrings)
	return strings.Join(endpointsStrings, commaSeparator)
}

func (g *groupedExternalNodes) String() string {
	// 1. Created a list of IPBlocks
	cidrList := make([]string, len(*g))
	for i, n := range *g {
		cidrList[i] = n.CidrStr
	}
	ipbList, _, err := ipStringsToIPblocks(cidrList)
	if err != nil {
		return ""
	}
	// 2. Union all IPBlocks in a single one; its intervals will be the cidr blocks or ranges that should be printed, after all possible merges
	unionBlock := ipblock.New()
	for _, ipBlock := range ipbList {
		unionBlock = unionBlock.Union(ipBlock)
	}
	// 3. print a list s.t. each element contains either a single cidr or an ip range
	return strings.Join(unionBlock.ListToPrint(), commaSeparator)
}

// connDiffEncode encodes connectivesDiff information for grouping:
// this includes the following 4 strings separated by ";"
//  1. diff-type info: e.g. diff-type: removed
//  2. connection of config1
//  3. connection of config2
//  4. info regarding missing endpoints: e.g. vsi0 removed
func connDiffEncode(src, dst VPCResourceIntf, connDiff *connectionDiff) string {
	conn1Str, conn2Str := conn1And2Str(connDiff)
	diffType, endpointsDiff := diffAndEndpointsDescription(connDiff.diff, src, dst, connDiff.thisMinusOther)
	return strings.Join([]string{diffType, conn1Str, conn2Str, endpointsDiff}, semicolon)
}

// encodes rulesConnection for grouping
func (details *srcDstDetails) explanationEncode(c *VPCConfig) string {
	connStr := details.conn.String() + semicolon
	routingStr := ""
	if details.router != nil {
		routingStr = details.router.Name() + ";"
	}
	egressStr, ingressStr := "", ""
	if len(details.actualMergedRules.egressRules) > 0 {
		egressStr = "egress:" + details.actualMergedRules.egressRules.rulesDetailsStr(c, details.filtersRelevant,
			false) + semicolon
	}
	if len(details.actualMergedRules.ingressRules) > 0 {
		egressStr = "ingress:" + details.actualMergedRules.ingressRules.rulesDetailsStr(c, details.filtersRelevant,
			true) + semicolon
	}
	return connStr + routingStr + egressStr + ingressStr
}
