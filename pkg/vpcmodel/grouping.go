package vpcmodel

import (
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

func newGroupConnLinesSubnetConnectivity(c *CloudConfig, s *VPCsubnetConnectivity) *GroupConnLines {
	res := &GroupConnLines{c: c, s: s, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	res.groupExternalAddressesForSubnets()
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

type groupedNetworkInterfaces []Node

func (g *groupedNetworkInterfaces) Name() string {
	return listNodesStr(*g, Node.Name)
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

// subnetGrouping returns a slice of EndpointElem objects produced from an input slice, by grouping
// set of elements that represent network interface nodes from the same subnet into a single groupedNetworkInterfaces object
func subnetGrouping(elemsList []EndpointElem, c *CloudConfig) []EndpointElem {
	res := []EndpointElem{}
	subnetNameToNodes := map[string][]Node{} // map from subnet name to its nodes from the input
	for _, elem := range elemsList {
		n, ok := elem.(Node)
		if !ok {
			res = append(res, n) // elements which are not interface nodes remain in the result as in the original input
			continue             // skip input elements which are not a network interface node
		}
		subnetName := c.getSubnetOfNode(n).Name() // get the subnet to which n belongs
		if _, ok := subnetNameToNodes[subnetName]; !ok {
			subnetNameToNodes[subnetName] = []Node{}
		}
		subnetNameToNodes[subnetName] = append(subnetNameToNodes[subnetName], n)
	}
	for _, nodesList := range subnetNameToNodes {
		if len(nodesList) == 1 { // a single network interface on subnet is just added to the result (no grouping)
			res = append(res, nodesList[0])
		} else { // a set of network interfaces from the same subnet is grouped by groupedNetworkInterfaces object
			groupedNodes := groupedNetworkInterfaces(nodesList)
			res = append(res, &groupedNodes)
		}
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
			hasExternal := false
			switch dst.(type) {
			case Node:
				if dst.(Node).IsPublicInternet() {
					hasExternal = true
					g.srcToDst.addPublicConnectivity(src, connString, dst.(Node))
				}
			}
			// since pgw enable only egress src can not be public internet
			// not an external connection in source or destination - nothing to group, just append
			if !hasExternal {
				res = append(res, &GroupedConnLine{src, dst, connString})
			}
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(true)...)
	res = append(res, g.dstToSrc.getGroupedConnLines(false)...)
	g.GroupedLines = res
}

// assuming the  g.groupedLines was already initialized by previous step groupExternalAddresses()
func (g *GroupConnLines) groupSubnetsSrcOrDst(srcGrouping bool) {
	res := []*GroupedConnLine{}
	// build map from str(dst+conn) to []src => create lines accordingly
	groupingSrcOrDst := map[string][]*GroupedConnLine{}

	// populate map groupingSrcOrDst
	for _, line := range g.GroupedLines {
		srcOrDst, dstOrSrc := line.getSrcOrDst(srcGrouping), line.getSrcOrDst(!srcGrouping)
		if _, ok := srcOrDst.(Node); !ok {
			res = append(res, line)
			continue
		}
		key := dstOrSrc.Name() + ";" + line.Conn
		if _, ok := groupingSrcOrDst[key]; !ok {
			groupingSrcOrDst[key] = []*GroupedConnLine{}
		}
		groupingSrcOrDst[key] = append(groupingSrcOrDst[key], line)
	}

	// update g.groupedLines based on groupingSrcOrDst
	for _, linesGroup := range groupingSrcOrDst {
		// if linesGroup.Src contains set of interfaces from the same subnet => group to one line with those interfaces
		// else, keep separated lines
		srcOrDstGroup := make([]EndpointElem, len(linesGroup))
		for i, line := range linesGroup {
			srcOrDstGroup[i] = line.getSrcOrDst(srcGrouping)
		}
		groupedSrcOrDst := subnetGrouping(srcOrDstGroup, g.c)
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
		g.groupSubnetsSrcOrDst(true)
		g.groupSubnetsSrcOrDst(false)
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

func listNodesStr(nodes []Node, fn func(Node) string) string {
	nodesStrings := make([]string, len(nodes))
	for i, n := range nodes {
		nodesStrings[i] = fn(n)
	}
	sort.Strings(nodesStrings)
	return strings.Join(nodesStrings, ",")
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
