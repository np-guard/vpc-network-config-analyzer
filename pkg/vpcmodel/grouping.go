package vpcmodel

import (
	"sort"
	"strings"
)

type groupingConnections map[Node]map[string][]Node // for each line here can group list of external nodes to cidrs list as of one element

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
	res := groupingConnections(map[Node]map[string][]Node{})
	return &res
}

func newGroupConnLines(c *CloudConfig, v *VPCConnectivity) *GroupConnLines {
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	res.computeGrouping()
	return res
}

type GroupConnLines struct {
	c            *CloudConfig
	v            *VPCConnectivity
	srcToDst     *groupingConnections
	dstToSrc     *groupingConnections
	GroupedLines []*GroupedConnLine
}

// EndpointElem can be Node(networkInterface) / NodeSet(subnet) / groupedExternalNodes
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

// implements endpointElem interface
type groupedExternalNodes []Node

func (g *groupedExternalNodes) Name() string {
	isAllInternetRange, err := isEntirePublicInternetRange(*g)
	if err == nil && isAllInternetRange {
		return "Public Internet (all ranges)"
	}
	nodesStrings := make([]string, len(*g))
	for i, n := range *g {
		nodesStrings[i] = n.Cidr()
	}
	sort.Strings(nodesStrings)
	return strings.Join(nodesStrings, ",")
}

func (g *groupingConnections) addPublicConnectivity(n Node, conn string, target Node) {
	if _, ok := (*g)[n]; !ok {
		(*g)[n] = map[string][]Node{}
	}
	if _, ok := (*g)[n][conn]; !ok {
		(*g)[n][conn] = []Node{}
	}
	(*g)[n][conn] = append((*g)[n][conn], target)
}

// subnetGrouping returns a slice of EndpointElem objects produced from an input slice, by grouping
// set of elements that represent network interface nodes into a single subnet node, if all the
// subnet's interfaces are in the input slice
func subnetGrouping(elemsList []EndpointElem, c *CloudConfig) []EndpointElem {
	res := []EndpointElem{}
	subnetNameToNodes := map[string][]Node{} // map from subnet name to its nodes from the input
	groupedSubnets := map[string]bool{}      // map from subnet name to bool indicating if it was grouped
	for _, elem := range elemsList {
		n, ok := elem.(Node)
		if !ok {
			res = append(res, n) // elements which are not interface nodes remain in the result as in the original input
			continue             // skip input elements which are not a network interface node
		}
		subnet := c.getSubnetOfNode(n) // get the subnet to which n belongs
		subnetName := subnet.Name()
		if _, ok := subnetNameToNodes[subnetName]; !ok {
			subnetNameToNodes[subnetName] = []Node{}
			groupedSubnets[subnetName] = false
		}
		subnetNameToNodes[subnetName] = append(subnetNameToNodes[subnetName], n)
		// if all interfaces on the current node's subnet were in the input elemsList, mark the subnet as grouped
		if len(subnetNameToNodes[subnetName]) == len(subnet.Nodes()) {
			res = append(res, subnet) // add to the result the grouped subnet (which will replace all its interfaces from the input)
			groupedSubnets[subnetName] = true
		}
	}
	// for each subnet that was not grouped, add its interface nodes from the input to the result
	for subnetStr, isGrouped := range groupedSubnets {
		if !isGrouped {
			for _, node := range subnetNameToNodes[subnetStr] {
				res = append(res, node)
			}
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
			connString := conns.String()
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
		// if linesGroup.Src contains an entire subnet => group to one line with subnet
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

func (g *GroupConnLines) computeGrouping() {
	g.groupExternalAddresses()
	g.groupSubnetsSrcOrDst(true)
	g.groupSubnetsSrcOrDst(false)
}

// get the grouped connectivity output
func (g *GroupConnLines) String() string {
	linesStr := make([]string, len(g.GroupedLines))
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n")
}
