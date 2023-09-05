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
	newGroupingSrcOrDst := g.extendGroupingSelfLoops(groupingSrcOrDst, srcGrouping)
	return res, newGroupingSrcOrDst
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

// extends grouping by considering self loops https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func (g *GroupConnLines) extendGroupingSelfLoops(groupingSrcOrDst map[string][]*GroupedConnLine,
	srcGrouping bool) map[string][]*GroupedConnLine {
	toMergeCouples := g.groupsToBeMerged(groupingSrcOrDst, srcGrouping)
	return mergeSelfLoops(toMergeCouples, groupingSrcOrDst, srcGrouping)
}

func (g *GroupConnLines) groupsToBeMerged(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool) (toMergeCouples [][2]string) {
	toMergeCouples = make([][2]string, 0)
	// the to be grouped src/dst in set representation, will be needed to compute the deltas
	setsToGroup := createGroupingSets(groupingSrcOrDst, srcGrouping)
	// in order to compare each couple only once, compare only couples in one half of the matrix.
	// To that end we must define an order and travers it - sorted sortedKeys
	sortedKeys := make([]string, 0, len(groupingSrcOrDst))

	for k := range groupingSrcOrDst {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, outerKey := range sortedKeys {
		outerLines := groupingSrcOrDst[outerKey]
		// 1. relevant only if both source and destination refers to vsis/subnets
		//    src/dst of lines grouped together are either all external or all internal. So it suffice to check for the first line in a group
		if outerLines[0].isSrcOrDstExternalNodes() {
			continue
		}
		// 2. is there a different line s.t. the outerLines were not merged only due to self loops?
		// 	  going over all couples of items: merging them if they differ only in self loop element
		//    need to go over all couples of lines grouping no ordering; need only one half of the matrix
		halfMatrix := true
		for _, innerKey := range sortedKeys {
			innerLines := groupingSrcOrDst[innerKey]
			// 2.1 not the same line
			if innerKey == outerKey {
				halfMatrix = false
				continue
			}
			if !halfMatrix { // delta is symmetric, no need to calculate twice
				continue
			}
			// 2.2 again, both src and dst of grouped lines must refer to subnets/vsis
			if innerLines[0].isSrcOrDstExternalNodes() {
				continue
			}
			// 2.3 both lines must be with the same connection
			if outerLines[0].Conn != innerLines[0].Conn { // note that all connections are identical in each of the outerLines and innerLines
				continue
			}
			// 2.4 if grouping vsis then src of compared groups and destinations of compared groups must be same subnet
			if g.vsisNotSameSameSubnet(outerLines[0].Src, innerLines[0].Src) || g.vsisNotSameSameSubnet(outerLines[0].Dst, innerLines[0].Dst) {
				continue
			}
			// 2.4 delta between outerKeyEndPointElements to innerKeyEndPointElements must be 0
			mergeGroups := deltaBetweenGroupedConnLines(srcGrouping, outerLines, innerLines, setsToGroup[outerKey], setsToGroup[innerKey])
			// 2.5 delta between the outerLines is 0 - merge outerLines
			if mergeGroups {
				var toMerge = [2]string{outerKey, innerKey}
				toMergeCouples = append(toMergeCouples, toMerge)
			}
		}
	}
	return
}

// if the two endpoints are vsis and do not belong to the same subnet returns true, otherwise false
// an endpoint can also be a slice of vsis, in which case the invariant is that they belong to the same subnet
func (g *GroupConnLines) vsisNotSameSameSubnet(ep1, ep2 EndpointElem) bool {
	isVsi1, node1 := isEpVsi(ep1)
	isVsi2, node2 := isEpVsi(ep2)
	if !isVsi1 || !isVsi2 {
		return false
	}
	return g.c.getSubnetOfNode(node1).Name() != g.c.getSubnetOfNode(node2).Name()
}

// returns true, vsi if the endpoint element represents a vsi or is a slice of elements the first of which represents vsi
// otherwise returns false, nil
func isEpVsi(ep EndpointElem) (bool, Node) {
	if _, ok := ep.(*groupedEndpointsElems); ok {
		ep1GroupedEps := ep.(*groupedEndpointsElems)
		for _, ep := range *ep1GroupedEps {
			if _, ok := ep.(Node); ok {
				if ep.(Node).IsInternal() {
					return true, ep.(Node)
				} else {
					return false, nil
				}
			} else { // is NodeSet
				return false, nil
			}
		}
	}
	if _, ok := ep.(Node); ok {
		if ep.(Node).IsInternal() {
			return true, ep.(Node)
		}
	}
	return false, nil
}

// creates an aux database in which all the grouped endpoints are stored in a set
func createGroupingSets(groupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool) map[string]map[string]struct{} {
	keyToGroupedSets := make(map[string]map[string]struct{})
	for key, groupedConnLine := range groupingSrcOrDst {
		mySet := make(map[string]struct{})
		for _, line := range groupedConnLine {
			srcOrDst := line.getSrcOrDst(srcGrouping)
			mySet[srcOrDst.Name()] = struct{}{}
		}
		keyToGroupedSets[key] = mySet
	}
	return keyToGroupedSets
}

// computes delta between group connection lines https://github.com/np-guard/vpc-network-config-analyzer/issues/98
func deltaBetweenGroupedConnLines(srcGrouping bool, groupedConnLine1, groupedConnLine2 []*GroupedConnLine,
	setToGroup1, setToGroup2 map[string]struct{}) bool {
	// at least one of the keys must be a single vsi/subnet for the self loop check to be meaningful
	if elemInKeys(srcGrouping, *groupedConnLine1[0]) > 1 && elemInKeys(srcGrouping, *groupedConnLine2[0]) > 1 {
		return false
	}
	// is there is a real delta between sets and not only due to self loop
	set1MinusSet2 := setMinusSet(srcGrouping, *groupedConnLine2[0], setToGroup1, setToGroup2)
	set2MinusSet1 := setMinusSet(srcGrouping, *groupedConnLine1[0], setToGroup2, setToGroup1)
	if len(set1MinusSet2) == 0 && len(set2MinusSet1) == 0 {
		return true
	}
	return false
}

func elemInKeys(srcGrouping bool, groupedConnLine GroupedConnLine) int {
	srcOrDst := groupedConnLine.getSrcOrDst(srcGrouping)
	return len(strings.Split(srcOrDst.Name(), ","))
}

func setMinusSet(srcGrouping bool, groupedConnLine GroupedConnLine, set1, set2 map[string]struct{}) map[string]struct{} {
	minusResult := make(map[string]struct{})
	for k := range set1 {
		if _, ok := set2[k]; !ok {
			minusResult[k] = struct{}{}
		}
	}
	// if set2's groupedConnLine key has a single item, then this single item is not relevant to the delta
	// since any EndpointElement is connected to itself
	if elemInKeys(srcGrouping, groupedConnLine) == 1 {
		keyOfGrouped2 := groupedConnLine.getSrcOrDst(!srcGrouping) // all non-grouping items are the same in a groupedConnLine
		delete(minusResult, keyOfGrouped2.Name())                  // if keyOfGrouped2.Name() does not exist in minusResult then this is no-op
	}
	return minusResult
}

func (g *GroupedConnLine) isSrcOrDstExternalNodes() bool {
	if _, ok := g.Src.(*groupedExternalNodes); ok {
		return true
	}
	if _, ok := g.Dst.(*groupedExternalNodes); ok {
		return true
	}
	return false
}

func mergeSelfLoops(toMergeCouples [][2]string, oldGroupingSrcOrDst map[string][]*GroupedConnLine,
	srcGrouping bool) map[string][]*GroupedConnLine {
	// 1. Create dedicated data structure: a slice of slices of string toMergeList s.t. each slice contains a list of keys to be merged
	//    and a map toMergeExistingIndexes between key to its index in the slice
	toMergeList := make([][]string, 0, 0)
	toMergeExistingIndexes := make(map[string]int)
	for _, coupleKeys := range toMergeCouples {
		existingIndx1, ok1 := toMergeExistingIndexes[coupleKeys[0]]
		existingIndx2, ok2 := toMergeExistingIndexes[coupleKeys[1]]
		switch ok1 {
		case true:
			if !ok2 {
				toMergeExistingIndexes[coupleKeys[1]] = existingIndx1
				toMergeList[existingIndx1] = append(toMergeList[existingIndx1], coupleKeys[1])
			}
		case false:
			if ok2 {
				toMergeExistingIndexes[coupleKeys[0]] = existingIndx2
				toMergeList[existingIndx2] = append(toMergeList[existingIndx2], coupleKeys[0])
			} else {
				// if both []*GroupedConnLine already exist in toMergeExistingIndexes then existingIndx1 equals existingIndx2 and nothing to be done here
				nextIndx := len(toMergeList)
				toMergeExistingIndexes[coupleKeys[0]], toMergeExistingIndexes[coupleKeys[1]] = nextIndx, nextIndx
				newList := []string{coupleKeys[0], coupleKeys[1]}
				toMergeList = append(toMergeList, newList)
			}
		}
	}
	// 2. Performs the actual merge
	//    Build New map[string][]*GroupedConnLine :
	mergedGroupedConnLine := make(map[string][]*GroupedConnLine)
	//    2.1 go over the new data structure, merge groups to be merged and add to New
	//    2.2 go over old map[string][]*GroupedConnLine and for each element whose key not in toMergeKeys then just add it as is
	for _, toBeMergedKeys := range toMergeList {
		newKey, newGroupedConnLines := mergeGivenList(oldGroupingSrcOrDst, srcGrouping, toBeMergedKeys)
		mergedGroupedConnLine[newKey] = newGroupedConnLines
	}
	for oldKey, oldLines := range oldGroupingSrcOrDst {
		// not merged with other groups, add as is
		if _, ok := toMergeExistingIndexes[oldKey]; !ok {
			mergedGroupedConnLine[oldKey] = oldLines
		}
	}
	return mergedGroupedConnLine
}

// given a list of keys to be merged from of oldGroupingSrcOrDst, computes unique list of endpoints
// of either sources or destination as by srcGrouping
// returns the unique list of endpoints, their names and the connection
func listOfUniqueEndpoints(oldGroupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool,
	toMergeKeys []string) (listOfEndpoints groupedEndpointsElems, setOfNames map[string]struct{}, conn string) {
	setOfNames = make(map[string]struct{})
	listOfEndpoints = make(groupedEndpointsElems, 0, 0)
	for _, oldKeyToMerge := range toMergeKeys {
		for _, line := range oldGroupingSrcOrDst[oldKeyToMerge] {
			endPointInKey := line.getSrcOrDst(!srcGrouping)
			if conn == "" {
				conn = line.Conn // connection is the same for all lines to be merged
			}
			if _, isSliceEndpoints := endPointInKey.(*groupedEndpointsElems); isSliceEndpoints {
				for _, endpoint := range *endPointInKey.(*groupedEndpointsElems) {
					if _, ok := setOfNames[endpoint.Name()]; !ok { // was endpoint added already?
						listOfEndpoints = append(listOfEndpoints, endpoint)
						setOfNames[endpoint.Name()] = struct{}{}
					}
				}
			} else { // endpoint is Node or NodeSet
				if _, ok := setOfNames[endPointInKey.Name()]; !ok { // was endpoint added already?
					listOfEndpoints = append(listOfEndpoints, endPointInKey)
					setOfNames[endPointInKey.Name()] = struct{}{}
				}
			}
		}
	}
	return
}

func mergeGivenList(oldGroupingSrcOrDst map[string][]*GroupedConnLine, srcGrouping bool,
	toMergeKeys []string) (newKey string, newGroupedConnLine []*GroupedConnLine) {
	epsInNewKey, namesInNewKey, _ := listOfUniqueEndpoints(oldGroupingSrcOrDst, srcGrouping, toMergeKeys)
	epsInNewLines, _, conn := listOfUniqueEndpoints(oldGroupingSrcOrDst, !srcGrouping, toMergeKeys)
	for _, epInLineValue := range epsInNewLines {
		if srcGrouping {
			newGroupedConnLine = append(newGroupedConnLine, &GroupedConnLine{epInLineValue, &epsInNewKey, conn})
		} else {
			newGroupedConnLine = append(newGroupedConnLine, &GroupedConnLine{&epsInNewKey, epInLineValue, conn})
		}
	}
	srcsOrDstsInNewKeySlice := make([]string, 0, 0)
	for item := range namesInNewKey {
		srcsOrDstsInNewKeySlice = append(srcsOrDstsInNewKeySlice, item)
	}
	newKey = strings.Join(srcsOrDstsInNewKeySlice, ",") + conn
	return
}
