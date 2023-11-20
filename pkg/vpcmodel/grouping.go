package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const commaSeparator = ","

// for each line here can group list of external nodes to cidrs list as of one element
type groupingConnections map[EndpointElem]map[string][]Node

func (g *groupingConnections) getGroupedConnLines(groupedConnLines *GroupConnLines,
	isSrcToDst bool) []*GroupedConnLine {
	res := []*GroupedConnLine{}
	for a, aMap := range *g {
		for conn, b := range aMap {
			var resElem *GroupedConnLine
			bGrouped := groupedConnLines.getGroupedExternalNodes(b)
			if isSrcToDst {
				resElem = &GroupedConnLine{a, bGrouped, conn}
			} else {
				resElem = &GroupedConnLine{bGrouped, a, conn}
			}
			res = append(res, resElem)
		}
	}
	return res
}

func newGroupingConnections() *groupingConnections {
	res := groupingConnections(map[EndpointElem]map[string][]Node{})
	return &res
}

func newGroupConnLines(c *VPCConfig, v *VPCConnectivity, grouping bool) *GroupConnLines {
	res := &GroupConnLines{c: c, v: v,
		srcToDst:                 newGroupingConnections(),
		dstToSrc:                 newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.computeGrouping(grouping)
	return res
}

func newGroupConnLinesSubnetConnectivity(c *VPCConfig, s *VPCsubnetConnectivity, grouping bool) *GroupConnLines {
	res := &GroupConnLines{c: c, s: s,
		srcToDst:                 newGroupingConnections(),
		dstToSrc:                 newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.computeGroupingForSubnets(grouping)
	return res
}

func newGroupConnLinesDiff(d *diffBetweenCfgs) *GroupConnLines {
	res := &GroupConnLines{d: d,
		srcToDst:                 newGroupingConnections(),
		dstToSrc:                 newGroupingConnections(),
		groupedEndpointsElemsMap: make(map[string]*groupedEndpointsElems),
		groupedExternalNodesMap:  make(map[string]*groupedExternalNodes)}
	res.computeGroupingForDiff()
	return res
}

// GroupConnLines used both for VPCConnectivity and for VPCsubnetConnectivity, one at a time. The other must be nil
// todo: define abstraction above both?
type GroupConnLines struct {
	c        *VPCConfig
	v        *VPCConnectivity
	s        *VPCsubnetConnectivity
	d        *diffBetweenCfgs
	srcToDst *groupingConnections
	dstToSrc *groupingConnections
	// a map to groupedEndpointsElems used by GroupedConnLine from a unified key of such elements
	// representing grouped vsis or grouped subnets
	// this is to avoid duplication of identical groupedEndpointsElems
	groupedEndpointsElemsMap map[string]*groupedEndpointsElems
	// similarly to the above, such map to groupedExternalNodes
	groupedExternalNodesMap map[string]*groupedExternalNodes
	GroupedLines            []*GroupedConnLine
}

// EndpointElem can be Node(networkInterface) / groupedExternalNodes / groupedNetworkInterfaces / NodeSet(subnet)
type EndpointElem interface {
	Name() string
	DrawioResourceIntf
}

type GroupedConnLine struct {
	Src  EndpointElem
	Dst  EndpointElem
	Conn string
}

func (g *GroupedConnLine) String() string {
	return g.Src.Name() + " => " + g.Dst.Name() + " : " + g.Conn
}

func (g *GroupedConnLine) ConnLabel() string {
	// todo - this info can be found in the conn struct, GroupedConnLine should keep the struct instead of just a string
	if common.IsAllConnections(g.Conn) {
		return ""
	}
	return g.Conn
}

func (g *GroupedConnLine) getSrcOrDst(isSrc bool) EndpointElem {
	if isSrc {
		return g.Src
	}
	return g.Dst
}

type groupedEndpointsElems []EndpointElem

func (g *groupedEndpointsElems) Name() string {
	return listEndpointElemStr(*g, EndpointElem.Name)
}

func (g *groupedEndpointsElems) IsExternal() bool {
	return false
}

// implements endpointElem interface
type groupedExternalNodes []Node

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

// given a groupedEndpointsElems returns an equiv item from groupedEndpointsElemsMap if exists,
// or adds it to groupedEndpointsElemsMap if such an item does not exist
func (g *GroupConnLines) getGroupedEndpointsElems(grouped groupedEndpointsElems) *groupedEndpointsElems {
	// since the endpoints (vsis/subnets) are sorted before printed, grouped.Name() will be identical
	// to equiv groupedEndpointsElems
	if existingGrouped, ok := g.groupedEndpointsElemsMap[grouped.Name()]; ok {
		return existingGrouped
	}
	g.groupedEndpointsElemsMap[grouped.Name()] = &grouped
	return &grouped
}

// same as the previous function, for groupedExternalNodesMap
func (g *GroupConnLines) getGroupedExternalNodes(grouped groupedExternalNodes) *groupedExternalNodes {
	// Due to the canonical representation, grouped.String() and thus grouped.Name() will be identical
	//  to equiv groupedExternalNodes
	if existingGrouped, ok := g.groupedExternalNodesMap[grouped.Name()]; ok {
		return existingGrouped
	}
	g.groupedExternalNodesMap[grouped.Name()] = &grouped
	return &grouped
}

func (g *groupingConnections) addPublicConnectivity(ep EndpointElem, conn string, targetNode Node) {
	if _, ok := (*g)[ep]; !ok {
		(*g)[ep] = map[string][]Node{}
	}
	if _, ok := (*g)[ep][conn]; !ok {
		(*g)[ep][conn] = []Node{}
	}
	(*g)[ep][conn] = append((*g)[ep][conn], targetNode)
}

// vsiGroupingBySubnets returns a slice of EndpointElem objects, by grouping set of elements that
// represent network interface nodes from the same subnet into a single groupedNetworkInterfaces object
func vsiGroupingBySubnets(groupedConnLines *GroupConnLines,
	elemsList []EndpointElem, c *VPCConfig) []EndpointElem {
	res := []EndpointElem{}
	subnetNameToNodes := map[string][]EndpointElem{} // map from subnet name to its nodes from the input
	for _, elem := range elemsList {
		n, ok := elem.(Node)
		if !ok {
			res = append(res, n) // elements which are not interface nodes remain in the result as in the original input
			continue             // skip input elements which are not a network interface node
		}
		subnetName := c.getSubnetOfNode(n).Name() // get the subnet to which n belongs
		if _, ok := subnetNameToNodes[subnetName]; !ok {
			subnetNameToNodes[subnetName] = []EndpointElem{}
		}
		subnetNameToNodes[subnetName] = append(subnetNameToNodes[subnetName], n)
	}
	for _, nodesList := range subnetNameToNodes {
		if len(nodesList) == 1 { // a single network interface on subnet is just added to the result (no grouping)
			res = append(res, nodesList[0])
		} else { // a set of network interfaces from the same subnet is grouped by groupedNetworkInterfaces object
			groupedNodes := groupedConnLines.getGroupedEndpointsElems(nodesList)
			res = append(res, groupedNodes)
		}
	}
	return res
}

// subnetGrouping returns a slice of EndpointElem objects produced from an input slice, by grouping
// set of elements that represent subnets into a single groupedNetworkInterfaces object
func subnetGrouping(groupedConnLines *GroupConnLines,
	elemsList []EndpointElem) []EndpointElem {
	res := []EndpointElem{}
	subnetsToGroup := []EndpointElem{} // subnets to be grouped
	for _, elem := range elemsList {
		n, ok := elem.(NodeSet)
		if !ok {
			res = append(res, n) // elements which are not NodeSet  remain in the result as in the original input
			continue             // NodeSet in the current context is a Subnet
		}
		subnetsToGroup = append(subnetsToGroup, n)
	}
	if len(subnetsToGroup) == 1 {
		res = append(res, subnetsToGroup[0])
	} else {
		groupedNodes := groupedConnLines.getGroupedEndpointsElems(subnetsToGroup)
		res = append(res, groupedNodes)
	}
	return res
}

func (g *GroupConnLines) groupExternalAddresses() {
	// phase1: group public internet ranges
	res := []*GroupedConnLine{}
	for src, nodeConns := range g.v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			g.addLineToExternalGrouping(&res, conns.IsEmpty(), src, dst, conns.EnhancedString())
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(g, true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(g, false)...)
	g.GroupedLines = res
}

func (g *GroupConnLines) groupExternalAddressesForSubnets() {
	// groups public internet ranges in dst when dst is public internet
	res := []*GroupedConnLine{}
	for src, endpointConns := range g.s.AllowedConnsCombined {
		for dst, conns := range endpointConns {
			// Note that since pgw enable only egress src can not actually be public internet
			g.addLineToExternalGrouping(&res, conns.IsEmpty(), src, dst, conns.EnhancedString())
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(g, true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(g, false)...)
	g.GroupedLines = res
}

func (g *GroupConnLines) groupExternalAddressesForDiff(thisMinusOther bool) {
	// group public internet ranges
	// initialize data structures
	g.srcToDst = newGroupingConnections()
	g.dstToSrc = newGroupingConnections()
	var res []*GroupedConnLine
	var connRemovedChanged connectivityDiff
	if thisMinusOther {
		connRemovedChanged = g.d.cfg1ConnRemovedFrom2
	} else {
		connRemovedChanged = g.d.cfg2ConnRemovedFrom1
	}
	for src, endpointConnDiff := range connRemovedChanged {
		for dst, connDiff := range endpointConnDiff {
			connDiffString := connDiffDecode(src, dst, connDiff, g.d.diffAnalysis, thisMinusOther)
			connsEmpty := connDiff.conn1.IsEmpty() && connDiff.conn2.IsEmpty()
			g.addLineToExternalGrouping(&res, connsEmpty, src, dst, connDiffString)
		}
	}

	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(g, true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(g, false)...)
	g.GroupedLines = append(g.GroupedLines, res...)
}

func (g *GroupConnLines) addLineToExternalGrouping(res *[]*GroupedConnLine, emptyConn bool,
	src, dst VPCResourceIntf, connEnhanced string) error {
	if emptyConn {
		return nil
	}
	srcNode, srcIsNode := src.(Node)
	dstNose, dstIsNode := dst.(Node)
	if dst.IsExternal() && !dstIsNode ||
		src.IsExternal() && !srcIsNode {
		msg := fmt.Sprintf("%v or %v is External but not a node", src.Name(), dst.Name())
		fmt.Println("error!:", msg) // todo: tmp
		return fmt.Errorf("%s", msg)
	}
	switch {
	case dst.IsExternal():
		g.srcToDst.addPublicConnectivity(src, connEnhanced, dstNose)
	case src.IsExternal():
		g.dstToSrc.addPublicConnectivity(dst, connEnhanced, srcNode)
	default:
		*res = append(*res, &GroupedConnLine{src, dst, connEnhanced})
	}
	return nil
}

// aux func, returns true iff the EndpointElem is Node if grouping vsis or NodeSet if grouping subnets
func isInternalOfRequiredType(ep EndpointElem, groupVsi bool) bool {
	if groupVsi { // groups vsis Nodes
		if _, ok := ep.(Node); !ok {
			return false
		}
	} else { // groups subnets NodeSets
		if _, ok := ep.(NodeSet); !ok {
			return false
		}
	}
	return true
}

// groups src/targets for either Vsis or Subnets
func (g *GroupConnLines) groupLinesByKey(srcGrouping, groupVsi bool) (res []*GroupedConnLine,
	groupingSrcOrDst map[string][]*GroupedConnLine) {
	res = []*GroupedConnLine{}
	// build map from str(dst+conn) to []src => create lines accordingly
	groupingSrcOrDst = map[string][]*GroupedConnLine{}
	// populate map groupingSrcOrDst
	for _, line := range g.GroupedLines {
		srcOrDst, dstOrSrc := line.getSrcOrDst(srcGrouping), line.getSrcOrDst(!srcGrouping)
		if !isInternalOfRequiredType(srcOrDst, groupVsi) {
			res = append(res, line)
			continue
		}
		key := getKeyOfGroupConnLines(dstOrSrc, line.Conn)
		if _, ok := groupingSrcOrDst[key]; !ok {
			groupingSrcOrDst[key] = []*GroupedConnLine{}
		}
		groupingSrcOrDst[key] = append(groupingSrcOrDst[key], line)
	}
	newGroupingSrcOrDst := g.extendGroupingSelfLoops(groupingSrcOrDst, srcGrouping)
	return res, newGroupingSrcOrDst
}

func getKeyOfGroupConnLines(ep EndpointElem, connection string) string {
	return ep.Name() + commaSeparator + connection
}

// assuming the  g.groupedLines was already initialized by previous step groupExternalAddresses()
func (g *GroupConnLines) groupInternalSrcOrDst(srcGrouping, groupVsi bool) {
	res, groupingSrcOrDst := g.groupLinesByKey(srcGrouping, groupVsi)

	// update g.groupedLines based on groupingSrcOrDst
	for _, linesGroup := range groupingSrcOrDst {
		// if linesGroup.Src contains set of interfaces from the same subnet => group to one line with those interfaces
		// else, keep separated lines
		srcOrDstGroup := make([]EndpointElem, len(linesGroup))
		for i, line := range linesGroup {
			srcOrDstGroup[i] = line.getSrcOrDst(srcGrouping)
		}
		var groupedSrcOrDst []EndpointElem
		if groupVsi {
			groupedSrcOrDst = vsiGroupingBySubnets(g, srcOrDstGroup, g.c)
		} else {
			groupedSrcOrDst = subnetGrouping(g, srcOrDstGroup)
		}
		for _, groupedSrcOrDstElem := range groupedSrcOrDst {
			if srcGrouping {
				res = append(res, &GroupedConnLine{groupedSrcOrDstElem, linesGroup[0].Dst, linesGroup[0].Conn})
			} else {
				res = append(res, &GroupedConnLine{linesGroup[0].Src, groupedSrcOrDstElem, linesGroup[0].Conn})
			}
		}
	}
	g.GroupedLines = g.unifiedGroupedConnLines(res)
}

// Go over the grouping result and make sure all groups have a unified reference.
// this is required due to the functionality treating self loops as don't cares - extendGroupingSelfLoops
// in which both srcs and dsts are manipulated  but *GroupConnLines is not familiar
// within the extendGroupingSelfLoops context and thus can not be done there smoothly
func (g *GroupConnLines) unifiedGroupedConnLines(oldConnLines []*GroupedConnLine) []*GroupedConnLine {
	newGroupedLines := make([]*GroupedConnLine, len(oldConnLines))
	// go over all connections; if src/dst is not external then use groupedEndpointsElemsMap
	for i, groupedConnLine := range oldConnLines {
		newGroupedLines[i] = &GroupedConnLine{g.unifiedGroupedElems(groupedConnLine.Src),
			g.unifiedGroupedElems(groupedConnLine.Dst),
			groupedConnLine.Conn}
	}
	return newGroupedLines
}

func (g *GroupConnLines) unifiedGroupedElems(srcOrDst EndpointElem) EndpointElem {
	if srcOrDst.IsExternal() { // external
		return srcOrDst
	}
	if _, ok := srcOrDst.(Node); ok { // vsi
		return srcOrDst
	}
	if _, ok := srcOrDst.(NodeSet); ok { // subnet
		return srcOrDst
	}
	groupedEE := srcOrDst.(*groupedEndpointsElems)
	unifiedGroupedEE := g.getGroupedEndpointsElems(*groupedEE)
	return unifiedGroupedEE
}

func (g *GroupConnLines) computeGrouping(grouping bool) {
	g.groupExternalAddresses()
	if grouping {
		g.groupInternalSrcOrDst(true, true)
		g.groupInternalSrcOrDst(false, true)
	}
}

func (g *GroupConnLines) computeGroupingForSubnets(grouping bool) {
	g.groupExternalAddressesForSubnets()
	if grouping {
		g.groupInternalSrcOrDst(false, false)
		g.groupInternalSrcOrDst(true, false)
	}
}

func (g *GroupConnLines) computeGroupingForDiff() {
	g.groupExternalAddressesForDiff(true)
	g.groupExternalAddressesForDiff(false)
}

// get the grouped connectivity output
func (g *GroupConnLines) String() string {
	linesStr := make([]string, len(g.GroupedLines))
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + asteriskDetails
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
		cidrList[i] = n.Cidr()
	}
	ipbList, _, err := ipStringsToIPblocks(cidrList)
	if err != nil {
		return ""
	}
	// 2. Union all IPBlocks in a single one; its intervals will be the cidr blocks or ranges that should be printed, after all possible merges
	unionBlock := &common.IPBlock{}
	for _, ipBlock := range ipbList {
		unionBlock = unionBlock.Union(ipBlock)
	}
	// 3. print a list s.t. each element contains either a single cidr or an ip range
	return strings.Join(unionBlock.ListToPrint(), commaSeparator)
}
