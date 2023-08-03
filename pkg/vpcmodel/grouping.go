package vpcmodel

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// map betweeen node to a map between a string containing connection;;IsStateful and the nodes connected through this connection
type groupingConnections map[Node]map[string][]Node // for each line here can group list of external nodes to cidrs list as of one element

func (g *groupingConnections) getGroupedConnLines(isSrcToDst bool) ([]*GroupedConnLine, error) {
	res := []*GroupedConnLine{}
	for a, aMap := range *g {
		for connWithStatefulness, b := range aMap {
			connWithStatefulnessSlice := strings.Split(connWithStatefulness, ";;")
			if len(connWithStatefulnessSlice) != 2 {
				return nil, fmt.Errorf("something wrong connWithStatefulnessSlice %+v is not in the right format; ", connWithStatefulness)
			}
			conn := connWithStatefulnessSlice[0]
			isStateful, _ := strconv.Atoi(connWithStatefulnessSlice[1])
			var resElem *GroupedConnLine
			bGrouped := groupedExternalNodes(b)
			if isSrcToDst {
				resElem = &GroupedConnLine{a, &bGrouped, conn, isStateful}
			} else {
				resElem = &GroupedConnLine{&bGrouped, a, conn, isStateful}
			}
			res = append(res, resElem)
		}
	}
	return res, nil
}

func newGroupingConnections() *groupingConnections {
	res := groupingConnections(map[Node]map[string][]Node{})
	return &res
}

func newGroupConnLines(c *CloudConfig, v *VPCConnectivity) (*GroupConnLines, error) {
	res := &GroupConnLines{c: c, v: v, srcToDst: newGroupingConnections(), dstToSrc: newGroupingConnections()}
	err := res.computeGrouping()
	return res, err
}

type GroupConnLines struct {
	c            *CloudConfig
	v            *VPCConnectivity
	srcToDst     *groupingConnections
	dstToSrc     *groupingConnections
	GroupedLines []*GroupedConnLine
}

// EndpointElem can be Node(networkInterface) / groupedExternalNodes / groupedNetworkInterfaces
type EndpointElem interface {
	Name() string
}

type GroupedConnLine struct {
	Src        EndpointElem
	Dst        EndpointElem
	Conn       string
	IsStateful int
}

func (g *GroupedConnLine) String() string {
	line := g.Src.Name() + " => " + g.Dst.Name() + " : " + g.Conn
	if g.IsStateful == common.StatefulFalse {
		line += " *"
	}
	return line
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
	if err == nil && isAllInternetRange {
		return "Public Internet (all ranges)"
	}
	return listNodesStr(*g, Node.Cidr)
}

func (g *groupingConnections) addPublicConnectivity(n Node, connWithStatefulness string, target Node) {
	if _, ok := (*g)[n]; !ok {
		(*g)[n] = map[string][]Node{}
	}
	if _, ok := (*g)[n][connWithStatefulness]; !ok {
		(*g)[n][connWithStatefulness] = []Node{}
	}
	(*g)[n][connWithStatefulness] = append((*g)[n][connWithStatefulness], target)
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

func (g *GroupConnLines) groupExternalAddresses() error {
	// phase1: group public internet ranges
	res := []*GroupedConnLine{}
	for src, nodeConns := range g.v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			connString := conns.String()
			connWithStatefulness := fmt.Sprintf("%s;;%d", connString, conns.IsStateful)
			switch {
			case dst.IsPublicInternet():
				g.srcToDst.addPublicConnectivity(src, connWithStatefulness, dst)
			case src.IsPublicInternet():
				g.dstToSrc.addPublicConnectivity(dst, connWithStatefulness, src)
			default:
				res = append(res, &GroupedConnLine{src, dst, connString, conns.IsStateful})
			}
		}
	}
	// add to res lines from  srcToDst and DstToSrc groupings
	resSrcToDst, err := g.srcToDst.getGroupedConnLines(true)
	if err != nil {
		return err
	}
	res = append(res, resSrcToDst...)
	resDstToSrc, err := g.dstToSrc.getGroupedConnLines(false)
	if err != nil {
		return err
	}
	res = append(res, resDstToSrc...)
	g.GroupedLines = res
	return nil
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
		key := fmt.Sprintf("%s;%s;%d", dstOrSrc.Name(), line.Conn, line.IsStateful)
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
				res = append(res, &GroupedConnLine{groupedSrcOrDstElem, linesGroup[0].Dst, linesGroup[0].Conn, linesGroup[0].IsStateful})
			} else {
				res = append(res, &GroupedConnLine{linesGroup[0].Src, groupedSrcOrDstElem, linesGroup[0].Conn, linesGroup[0].IsStateful})
			}
		}
	}

	g.GroupedLines = res
}

func (g *GroupConnLines) computeGrouping() error {
	err := g.groupExternalAddresses()
	if err != nil {
		return err
	}
	g.groupSubnetsSrcOrDst(true)
	g.groupSubnetsSrcOrDst(false)
	return nil
}

// get the grouped connectivity output
func (g *GroupConnLines) String() string {
	linesStr := make([]string, len(g.GroupedLines))
	addAsteriskDetails := false
	for i, line := range g.GroupedLines {
		linesStr[i] = line.String()
		if line.IsStateful == common.StatefulFalse {
			addAsteriskDetails = true
		}
	}
	sort.Strings(linesStr)
	toPrint := strings.Join(linesStr, "\n")
	if addAsteriskDetails {
		toPrint += asteriskDetails
	}
	return toPrint
}

func listNodesStr(nodes []Node, fn func(Node) string) string {
	nodesStrings := make([]string, len(nodes))
	for i, n := range nodes {
		nodesStrings[i] = fn(n)
	}
	sort.Strings(nodesStrings)
	return strings.Join(nodesStrings, ",")
}
