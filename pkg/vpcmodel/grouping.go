package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const commaSepartor = ","

// for each line here can group list of external nodes to cidrs list as of one element
type groupingConnections map[EndpointElem]map[string][]Node

func (g *groupingConnections) getGroupedConnLines(isSrcToDst bool) []*GroupedConnLine {
	res := []*GroupedConnLine{}
	for a, aMap := range *g {
		for conn, b := range aMap {
			var resElem *GroupedConnLine
			bGrouped := groupedExternalNodes(b)
			if isSrcToDst {
				resElem = &GroupedConnLine{a, &bGrouped, conn}
			} else {
				resElem = &GroupedConnLine{&bGrouped, a, conn}
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

func newGroupConnLines(c *CloudConfig, v *VPCConnectivity, grouping bool) *GroupConnLines {
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	res.computeGrouping(grouping)
	return res
}

func newGroupConnLinesSubnetConnectivity(c *CloudConfig, s *VPCsubnetConnectivity, grouping bool) *GroupConnLines {
	res := &GroupConnLines{c: c, s: s, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	res.computeGroupingForSubnets(grouping)
	return res
}

// GroupConnLines used both for VPCConnectivity and for VPCsubnetConnectivity, one at a time. The other must be nil
// todo: define abstraction above both?
type GroupConnLines struct {
	c            *CloudConfig
	v            *VPCConnectivity
	s            *VPCsubnetConnectivity
	srcToDst     *groupingConnections
	dstToSrc     *groupingConnections
	GroupedLines []*GroupedConnLine
}

// EndpointElem can be Node(networkInterface) / groupedExternalNodes / groupedNetworkInterfaces
type EndpointElem interface {
	Name() string
}

type GroupedConnLine struct {
	Src  EndpointElem
	Dst  EndpointElem
	Conn string
}

func (g *GroupedConnLine) String() string {
	return g.Src.Name() + " => " + g.Dst.Name() + " : " + g.Conn
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

// implements endpointElem interface
type groupedExternalNodes []Node

func (g *groupedExternalNodes) Name() string {
	isAllInternetRange, err := isEntirePublicInternetRange(*g)
	prefix := publicInternetNodeName + " "
	if err == nil && isAllInternetRange {
		return prefix + "(all ranges)"
	}
	return prefix + g.String()
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

// vsiGroupingBySubnets returns a slice of EndpointElem objects produced from an input slice, by grouping
// set of elements that represent network interface nodes from the same subnet into a single groupedNetworkInterfaces object
func vsiGroupingBySubnets(elemsList []EndpointElem, c *CloudConfig) []EndpointElem {
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
			groupedNodes := groupedEndpointsElems(nodesList)
			res = append(res, &groupedNodes)
		}
	}
	return res
}

// subnetGrouping returns a slice of EndpointElem objects produced from an input slice, by grouping
// set of elements that represent subnets into a single groupedNetworkInterfaces object
func subnetGrouping(elemsList []EndpointElem) []EndpointElem {
	res := []EndpointElem{}
	subnetsToGroup := make([]EndpointElem, 0) // subnets to be grouped
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
		groupedNodes := groupedEndpointsElems(subnetsToGroup)
		res = append(res, &groupedNodes)
	}
	return res
}

func (g *GroupConnLines) groupExternalAddresses() {
	// phase1: group public internet ranges
	res := []*GroupedConnLine{}
	for src, nodeConns := range g.v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			connString := conns.EnhancedString()
			switch {
			case dst.IsPublicInternet():
				g.srcToDst.addPublicConnectivity(src, connString, dst)
			case src.IsPublicInternet():
				g.dstToSrc.addPublicConnectivity(dst, connString, src)
			default:
				res = append(res, &GroupedConnLine{src, dst, connString})
			}
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(false)...)
	g.GroupedLines = res
}

func (g *GroupConnLines) groupExternalAddressesForSubnets() {
	// groups public internet ranges in dst when dst is public internet
	res := []*GroupedConnLine{}
	for src, endpointConns := range g.s.AllowedConnsCombined {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			connString := conns.EnhancedString()
			if dstNode, ok := dst.(Node); ok && dstNode.IsPublicInternet() {
				g.srcToDst.addPublicConnectivity(src, connString, dstNode)
			} else { // since pgw enable only egress src can not be public internet, the above is the only option of public internet
				// not an external connection in source or destination - nothing to group, just append
				res = append(res, &GroupedConnLine{src, dst, connString})
			}
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(false)...)
	g.GroupedLines = res
}

// aux func, returns true iff the EndpointElem is Node if grouping vsis or NodeSet if grouping subnets
func isInetrnalOfRequiredType(ep EndpointElem, groupVsi bool) bool {
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
		if !isInetrnalOfRequiredType(srcOrDst, groupVsi) {
			res = append(res, line)
			continue
		}
		key := dstOrSrc.Name() + ";" + line.Conn
		if _, ok := groupingSrcOrDst[key]; !ok {
			groupingSrcOrDst[key] = []*GroupedConnLine{}
		}
		groupingSrcOrDst[key] = append(groupingSrcOrDst[key], line)
	}
	extendGroupingSelfLoops(groupingSrcOrDst, srcGrouping)
	return res, groupingSrcOrDst
}

// extends grouping by considering self loops https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func extendGroupingSelfLoops(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool) {
	// todo: make sure ordering of iterating on a map is preserved
	fmt.Println("in extendGroupingSelfLoops, groupingSrcOrDst, srcGrouping is", srcGrouping)
	for outerKey, outerLines := range groupingSrcOrDst {
		// 1. relevant only if both source and destination refers to vsis/subnets
		//    src/dst of lines grouped together are either all external or all internal. So it suffice to check for the first line in a group
		if outerLines[0].isSrcOrDstExternalNodes() {
			continue
		}
		fmt.Printf("outerKey: %v\n", outerKey)
		for _, line := range outerLines {
			fmt.Println("\tline is", line)
			groupingItem := line.getSrcOrDst(srcGrouping)
			fmt.Printf("\tgroupingItem is:%+v outerLines of type %T\n", groupingItem.Name(), groupingItem)
		}
		// 2. is there a different line s.t. the outerLines were not merged only due to self loops?
		// 	  going over all couples of items: merging them if they differ only in self loop element
		// need to go over all couples of lines grouping no ordering; need only one half of the matrix
		preceedingEps := true
		for innerKey, innerLines := range groupingSrcOrDst {
			// 2.1 not the same line
			if innerKey == outerKey {
				preceedingEps = false
				continue
			}
			if preceedingEps {
				continue // first half of the matrix
			}
			// 2.2 again, both src and dst of grouped lines must refer to subnets/vsis
			if innerLines[0].isSrcOrDstExternalNodes() {
				continue
			}
			// 2.3 both lines must be with the same connection
			if outerLines[0].Conn != innerLines[0].Conn { // note that all connections are identical in each of the outerLines and innerLines
				continue
			}
			fmt.Printf("\t\tinnerKey: %v\n", innerKey)
			for _, line := range innerLines {
				fmt.Println("\t\t\tline is", line)
				groupingItem := line.getSrcOrDst(srcGrouping)
				fmt.Printf("\t\t\tgroupingItem is:%+v of type %T\n", groupingItem.Name(), groupingItem)
			}
			//innerKeyEndPointElements := innerLines[0].getSrcOrDst(!srcGrouping)
			//fmt.Printf("innerKeyEndPointElements is %v of type %T\n", innerKeyEndPointElements.Name(), innerKeyEndPointElements)
			// 2.4 delta between outerKeyEndPointElements to innerKeyEndPointElements must be 0
			// 2.5 delta between the outerLines is 0 - merge outerLines
		}
	}
}

// computes delta between group connection lines https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func deltaBetweenGroupedConnLines(groupedConnLine1, groupedConnLine2 []*GroupedConnLine, srcGrouping bool) bool {
	if len(groupedConnLine1) > 1 && len(groupedConnLine2) > 1 {
		return false
	}
	// delta between grouping item minus non-grouping item if singleton
	return false
}

func (g *GroupedConnLine) isSrcOrDstExternalNodes() bool {
	// todo: verify - is this the only possibility of external? can we have here an external node?
	if _, ok := g.Src.(*groupedExternalNodes); ok {
		return true
	}
	if _, ok := g.Dst.(*groupedExternalNodes); ok {
		return true
	}
	return false
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
			groupedSrcOrDst = vsiGroupingBySubnets(srcOrDstGroup, g.c)
		} else {
			groupedSrcOrDst = subnetGrouping(srcOrDstGroup)
		}
		for _, groupedSrcOrDstElem := range groupedSrcOrDst {
			if srcGrouping {
				res = append(res, &GroupedConnLine{groupedSrcOrDstElem, linesGroup[0].Dst, linesGroup[0].Conn})
			} else {
				res = append(res, &GroupedConnLine{linesGroup[0].Src, groupedSrcOrDstElem, linesGroup[0].Conn})
			}
		}
	}
	g.GroupedLines = res
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

// get the grouped connectivity output
func (g *GroupConnLines) String() string {
	linesStr := make([]string, len(g.GroupedLines))
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + asteriskDetails
}

// StringTmpWA ToDo: tmp WA until https://github.com/np-guard/vpc-network-config-analyzer/issues/138.
//
//	Once the issue is solved this code can be deleted
func (g *GroupConnLines) StringTmpWA() string {
	linesStr := make([]string, len(g.GroupedLines))
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n")
}

func listEndpointElemStr(eps []EndpointElem, fn func(ep EndpointElem) string) string {
	endpointsStrings := make([]string, len(eps))
	for i, ep := range eps {
		endpointsStrings[i] = fn(ep)
	}
	sort.Strings(endpointsStrings)
	return strings.Join(endpointsStrings, ",")
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
	return strings.Join(unionBlock.ListToPrint(), commaSepartor)
}
