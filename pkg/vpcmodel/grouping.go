package vpcmodel

import (
	"sort"
	"strings"
)

type ConnStr string

type GroupingConnections struct {
	publicConnectivity map[Node]map[ConnStr][]Node // for each line here can group list of external nodes to cidrs list as of one element
}

func (g *GroupingConnections) getGroupedConnLines(isSrcToDst bool) []*GroupedConnLine {
	res := []*GroupedConnLine{}
	for a, aMap := range g.publicConnectivity {
		for conn, b := range aMap {
			var resElem *GroupedConnLine
			if isSrcToDst {
				resElem = &GroupedConnLine{a, &GroupedExternalNodes{b}, conn}
			} else {
				resElem = &GroupedConnLine{&GroupedExternalNodes{b}, a, conn}
			}
			res = append(res, resElem)
		}
	}
	return res
}

func newGroupingConnections() *GroupingConnections {
	return &GroupingConnections{
		publicConnectivity: map[Node]map[ConnStr][]Node{},
	}
}

func newGroupConnLines(c *CloudConfig, v *VPCConnectivity) *GroupConnLines {
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), DstToSrc: newGroupingConnections()}
	res.computeGrouping()
	return res
}

type GroupConnLines struct {
	c            *CloudConfig
	v            *VPCConnectivity
	srcToDst     *GroupingConnections
	DstToSrc     *GroupingConnections
	GroupedLines []*GroupedConnLine
}

// EndpointElem can be Node(networkInterface) / NodeSet(subnet) / groupedExternalNodes
type EndpointElem interface {
	Name() string
}

type GroupedConnLine struct {
	Src  EndpointElem
	Dst  EndpointElem
	Conn ConnStr
}

func (g *GroupedConnLine) String() string {
	return g.Src.Name() + " => " + g.Dst.Name() + " : " + string(g.Conn)
}

func (g *GroupedConnLine) getSrcOrDst(isSrc bool) EndpointElem {
	if isSrc {
		return g.Src
	}
	return g.Dst
}

// implements endpointElem interface
type GroupedExternalNodes struct {
	nodes []Node
}

func (g *GroupedExternalNodes) Name() string {
	isAllIntenetRange, err := isEntirePublicInternetRange(g.nodes)
	if err == nil && isAllIntenetRange {
		return "Public Internet (all ranges)"
	}
	nodesStrings := make([]string, len(g.nodes))
	for i, n := range g.nodes {
		nodesStrings[i] = n.Cidr()
	}
	sort.Strings(nodesStrings)
	return strings.Join(nodesStrings, ",")
}

func (g *GroupingConnections) addPublicConnectivity(n Node, conn ConnStr, target Node) {
	if _, ok := g.publicConnectivity[n]; !ok {
		g.publicConnectivity[n] = map[ConnStr][]Node{}
	}
	if _, ok := g.publicConnectivity[n][conn]; !ok {
		g.publicConnectivity[n][conn] = []Node{}
	}
	g.publicConnectivity[n][conn] = append(g.publicConnectivity[n][conn], target)
}

func subnetGrouping(elemsList []EndpointElem, c *CloudConfig) []EndpointElem {
	res := []EndpointElem{}
	subnetNameToNodes := map[string][]Node{} // map from subnet name to its nodes from the input
	groupedSubnets := map[string]bool{}      // map from subnet name to bool indicating if it was grouped
	for _, elem := range elemsList {
		n, ok := elem.(Node)
		if !ok {
			continue
		}
		subnet := c.getSubnetOfNode(n)
		subnetName := subnet.Name()
		if _, ok := subnetNameToNodes[subnetName]; !ok {
			subnetNameToNodes[subnetName] = []Node{}
			groupedSubnets[subnetName] = false
		}
		subnetNameToNodes[subnetName] = append(subnetNameToNodes[subnetName], n)
		if len(subnetNameToNodes[subnetName]) == len(subnet.Nodes()) {
			res = append(res, subnet)
			groupedSubnets[subnetName] = true
		}
	}
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
			connString := ConnStr(conns.String())
			switch {
			case dst.IsPublicInternet():
				g.srcToDst.addPublicConnectivity(src, connString, dst)
			case src.IsPublicInternet():
				g.DstToSrc.addPublicConnectivity(dst, connString, src)
			default:
				res = append(res, &GroupedConnLine{src, dst, connString})
			}
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	res = append(res, g.srcToDst.getGroupedConnLines(true)...)
	res = append(res, g.DstToSrc.getGroupedConnLines(false)...)
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
		key := dstOrSrc.Name() + ";" + string(line.Conn)
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
		if groupedSrcOrDst != nil {
			for _, groupedSrcOrDstElem := range groupedSrcOrDst {
				if srcGrouping {
					res = append(res, &GroupedConnLine{groupedSrcOrDstElem, linesGroup[0].Dst, linesGroup[0].Conn})
				} else {
					res = append(res, &GroupedConnLine{linesGroup[0].Src, groupedSrcOrDstElem, linesGroup[0].Conn})
				}
			}
		} else {
			res = append(res, linesGroup...)
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
