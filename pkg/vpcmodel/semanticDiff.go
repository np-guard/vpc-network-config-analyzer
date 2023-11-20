package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type DiffType = int

const (
	noDiff DiffType = iota
	missingSrcEP
	missingDstEP
	missingSrcDstEP
	missingConnection
	changedConnection
)

type diffAnalysisType = int

const (
	Vsis diffAnalysisType = iota
	Subnets
)

const (
	castingNodeErr = "%s should be external node but casting to Node failed"
	diffTypeStr    = "diff-type:"
	configsStr     = "config1: %s, config2: %s, %s %s"
	semicolon      = ";"
)

type connectionDiff struct {
	conn1 *common.ConnectionSet
	conn2 *common.ConnectionSet
	diff  DiffType
}

type connectivityDiff map[VPCResourceIntf]map[VPCResourceIntf]*connectionDiff

type configsForDiff struct {
	config1      *VPCConfig
	config2      *VPCConfig
	diffAnalysis diffAnalysisType
}

type configConnectivity struct {
	config       *VPCConfig
	connectivity GeneralConnectivityMap
}

type diffBetweenCfgs struct {
	diffAnalysis diffAnalysisType

	cfg1ConnRemovedFrom2 connectivityDiff
	cfg2ConnRemovedFrom1 connectivityDiff

	// grouped connectivity result
	groupedLines []*GroupedConnLine
}

// GetDiff given 2 *VPCConfigs and an diff analysis - either subnets or endpoints -
// computes and returns the semantic diff of endpoints or subnets connectivity, as per the required analysis
func (configs configsForDiff) GetDiff() (*diffBetweenCfgs, error) {
	// 1. compute connectivity for each of the configurations
	generalConnectivityMap1, err := configs.config1.getAllowedConnectionsCombined(configs.diffAnalysis)
	if err != nil {
		return nil, err
	}
	generalConnectivityMap2, err := configs.config2.getAllowedConnectionsCombined(configs.diffAnalysis)
	if err != nil {
		return nil, err
	}

	// 2. Computes delta in both directions
	configConn1 := &configConnectivity{configs.config1,
		generalConnectivityMap1}
	configConn2 := &configConnectivity{configs.config2,
		generalConnectivityMap2}
	alignedConfigConnectivity1, alignedConfigConnectivity2, err :=
		configConn1.getConnectivesWithSameIPBlocks(configConn2)
	if err != nil {
		return nil, err
	}
	cfg1ConnRemovedFrom2, err1 := alignedConfigConnectivity1.connMissingOrChanged(alignedConfigConnectivity2, configs.diffAnalysis, true)
	if err1 != nil {
		return nil, err1
	}
	cfg2ConnRemovedFrom1, err2 := alignedConfigConnectivity2.connMissingOrChanged(alignedConfigConnectivity1, configs.diffAnalysis, false)
	if err2 != nil {
		return nil, err2
	}

	// 3. grouping
	res := &diffBetweenCfgs{
		cfg1ConnRemovedFrom2: cfg1ConnRemovedFrom2,
		cfg2ConnRemovedFrom1: cfg2ConnRemovedFrom1,
		diffAnalysis:         configs.diffAnalysis}
	groupConnLines, err1 := newGroupConnLinesDiff(res)
	if err1 != nil {
		return nil, err1
	}
	res.groupedLines = groupConnLines.GroupedLines
	return res, nil
}

func (c *VPCConfig) getAllowedConnectionsCombined(
	diffAnalysis diffAnalysisType) (generalConnectivityMap GeneralConnectivityMap, err error) {
	if diffAnalysis == Subnets {
		subnetsConn, err := c.GetSubnetsConnectivity(true, false)
		if err != nil {
			return nil, err
		}
		return subnetsConn.AllowedConnsCombined, err
	} else if diffAnalysis == Vsis {
		connectivity1, err := c.GetVPCNetworkConnectivity(false)
		if err != nil {
			return nil, err
		}
		return connectivity1.AllowedConnsCombined.nodesConnectivityToGeneralConnectivity(), nil
	}
	return nil, fmt.Errorf("illegal diff analysis type")
}

func (nodesConnMap NodesConnectionsMap) nodesConnectivityToGeneralConnectivity() (generalConnMap GeneralConnectivityMap) {
	generalConnMap = GeneralConnectivityMap{}
	for src, connsMap := range nodesConnMap {
		for dst, conn := range connsMap {
			if conn.IsEmpty() {
				continue
			}
			if _, ok := generalConnMap[src]; !ok {
				generalConnMap[src] = map[VPCResourceIntf]*common.ConnectionSet{}
			}
			generalConnMap[src][dst] = conn
		}
	}
	return generalConnMap
}

// for a given VPCResourceIntf (representing a subnet or an external ip) in config return the VPCResourceIntf representing the
// subnet/external address in otherConfig or nil if the subnet does not exist in the other config.
func (c *VPCConfig) getVPCResourceInfInOtherConfig(other *VPCConfig, ep VPCResourceIntf,
	diffAnalysis diffAnalysisType) (res VPCResourceIntf, err error) {
	if ep.IsExternal() {
		var node Node
		var ok bool
		if node, ok = ep.(Node); ok {
			nodeSameCidr := findNodeWithCidr(other.Nodes, ep.(Node).Cidr())
			return nodeSameCidr, nil
		}
		return nil, fmt.Errorf(castingNodeErr, node.Name())
	}
	// endpoint is a vsi or a subnet, depending on diffAnalysis value
	if diffAnalysis == Vsis {
		for _, node := range other.Nodes {
			if !node.IsInternal() {
				continue
			}
			if node.Name() == ep.Name() {
				res = VPCResourceIntf(node)
				return res, nil
			}
		}
	} else if diffAnalysis == Subnets {
		for _, nodeSet := range other.NodeSets {
			if nodeSet.Name() == ep.Name() {
				res = VPCResourceIntf(nodeSet)
				return res, nil
			}
		}
	}
	return nil, nil
}

// connMissingOrChanged of confConnectivity w.r.t. the other:
// connections may be identical, non-existing in other or existing in other but changed;
// the latter are included only if includeChanged, to avoid duplication in the final presentation
//
// assumption: any connection from connectivity and "other" have src (dst) which are either disjoint or equal
func (confConnectivity *configConnectivity) connMissingOrChanged(other *configConnectivity,
	diffAnalysis diffAnalysisType, includeChanged bool) (
	connectivityMissingOrChanged connectivityDiff, err error) {
	connectivityMissingOrChanged = map[VPCResourceIntf]map[VPCResourceIntf]*connectionDiff{}
	for src, endpointConns := range confConnectivity.connectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if _, ok := connectivityMissingOrChanged[src]; !ok {
				connectivityMissingOrChanged[src] = map[VPCResourceIntf]*connectionDiff{}
			}
			srcInOther, err1 := confConnectivity.config.getVPCResourceInfInOtherConfig(other.config, src, diffAnalysis)
			if err1 != nil {
				return nil, err1
			}
			dstInOther, err2 := confConnectivity.config.getVPCResourceInfInOtherConfig(other.config, dst, diffAnalysis)
			if err2 != nil {
				return nil, err2
			}
			connDiff := &connectionDiff{conns, nil, missingConnection}
			if srcInOther != nil && dstInOther != nil {
				if otherSrc, ok := other.connectivity[srcInOther]; ok {
					if otherConn, ok := otherSrc[dstInOther]; ok {
						equalConnections := conns.Equal(otherConn) &&
							// ToDo: https://github.com/np-guard/vpc-network-config-analyzer/issues/199
							conns.IsStateful == otherConn.IsStateful
						if !includeChanged || equalConnections {
							continue
						}
						connDiff.conn2 = otherConn
						connDiff.diff = changedConnection
					}
				}
			} else { // srcInOther == nil || dstInOther == nil
				connDiff.diff = getDiffType(src, srcInOther, dst, dstInOther)
			}
			connectivityMissingOrChanged[src][dst] = connDiff
		}
	}
	return connectivityMissingOrChanged, nil
}

// lack of a subnet is marked as a missing endpoint
// a lack of identical external endpoint is considered as a missing connection
// and not as a missing endpoint
func getDiffType(src, srcInOther, dst, dstInOther VPCResourceIntf) DiffType {
	srcIsInternal := !src.IsExternal()
	dstIsInternal := !dst.IsExternal()
	missingSrc := srcInOther == nil && srcIsInternal
	missingDst := dstInOther == nil && dstIsInternal
	switch {
	case missingSrc && missingDst:
		return missingSrcDstEP
	case missingSrc:
		return missingSrcEP
	case missingDst:
		return missingDstEP
	case srcInOther == nil || dstInOther == nil:
		return missingConnection
	}
	return noDiff
}

func (connDiff *connectivityDiff) string(diffAnalysis diffAnalysisType, thisMinusOther bool) string {
	strList := []string{}
	for src, endpointConnDiff := range *connDiff {
		for dst, connDiff := range endpointConnDiff {
			conn1Str, conn2Str := conn1And2Str(connDiff, thisMinusOther)
			diffType, endpointsDiff := diffAndEndpointsDisc(connDiff.diff, src, dst, thisMinusOther)
			diffInfo := diffInfoStr(diffAnalysis)
			printDiff := fmt.Sprintf("%v %s, source: %s, destination: %s, ", diffTypeStr, diffType, src.Name(), dst.Name())
			printDiff += fmt.Sprintf(configsStr, conn1Str, conn2Str, diffInfo, endpointsDiff) + "\n"
			strList = append(strList, printDiff)
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}

// connDiffEncode encodes connectivesDiff information for grouping:
// this includes the following two strings separated by ";"
//  1. diff-type info: e.g. diff-type: removed
//  2. configs info and info regarding missing endpoints:
//     e.g.: config1: All Connections, config2: No connection, vsis-diff-info: vsi0 removed
func connDiffEncode(src, dst VPCResourceIntf, connDiff *connectionDiff,
	diffAnalysis diffAnalysisType, thisMinusOther bool) string {
	conn1Str, conn2Str := conn1And2Str(connDiff, thisMinusOther)
	diffType, endpointsDiff := diffAndEndpointsDisc(connDiff.diff, src, dst, thisMinusOther)
	diffInfo := diffInfoStr(diffAnalysis)
	diffTypeStr := fmt.Sprintf("%v %s", diffTypeStr, diffType)
	connDiffStr := fmt.Sprintf(configsStr, conn1Str, conn2Str, diffInfo, endpointsDiff)
	return diffTypeStr + semicolon + connDiffStr
}

func diffInfoStr(diffAnalysis diffAnalysisType) string {
	if diffAnalysis == Subnets {
		return "subnets-diff-info:"
	} else if diffAnalysis == Vsis {
		return "vsis-diff-info:"
	}
	return ""
}

func conn1And2Str(connDiff *connectionDiff, thisMinusOther bool) (conn1Str, conn2Str string) {
	if thisMinusOther {
		conn1Str = connStr(connDiff.conn1)
		conn2Str = connStr(connDiff.conn2)
	} else {
		conn1Str = connStr(connDiff.conn2)
		conn2Str = connStr(connDiff.conn1)
	}
	return conn1Str, conn2Str
}

// connDiffDecode decode the above string
func connDiffDecode(src, dst EndpointElem, decoded string) string {
	encoded := strings.Split(decoded, semicolon)
	printDiff := fmt.Sprintf("%s, source: %s, destination: %s, %s\n", encoded[0], src.Name(), dst.Name(), encoded[1])
	return printDiff
}

func (diffCfgs *diffBetweenCfgs) String() string {
	strList := make([]string, len(diffCfgs.groupedLines))
	for i, grouped := range diffCfgs.groupedLines {
		strList[i] = connDiffDecode(grouped.Src, grouped.Dst, grouped.Conn)
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}

// prints connection for the above string(..) where the connection could be empty
func connStr(conn *common.ConnectionSet) string {
	if conn == nil {
		return "No connection"
	}
	return conn.EnhancedString()
}

func diffAndEndpointsDisc(diff DiffType, src, dst VPCResourceIntf, thisMinusOther bool) (diffDisc, workLoad string) {
	const (
		doubleString = "%s %s"
	)
	addOrRemoved := ""
	if thisMinusOther {
		addOrRemoved = "removed"
	} else {
		addOrRemoved = "added"
	}
	switch diff {
	case missingSrcEP:
		return addOrRemoved, fmt.Sprintf(doubleString, src.Name(), addOrRemoved)
	case missingDstEP:
		return addOrRemoved, fmt.Sprintf(doubleString, dst.Name(), addOrRemoved)
	case missingSrcDstEP:
		return addOrRemoved, fmt.Sprintf("%s and %s %s",
			src.Name(), dst.Name(), addOrRemoved)
	case missingConnection:
		return addOrRemoved, ""
	case changedConnection:
		return "changed", ""
	}
	return "", ""
}

// getConnectivesWithSameIPBlocks generates from the given GeneralConnectivityMap
// Two equivalent GeneralConnectivityMap objects s.t. any (src1, dst1) of the first map and
// (src2, dst2) of the 2nd map s.t. if src1 and src2 (dst1 and dst2) are both external then
// they are either equal or disjoint
func (confConnectivity *configConnectivity) getConnectivesWithSameIPBlocks(otherConfConnectivity *configConnectivity) (
	alignedConnectivityConfig, alignedOtherConnectivityConfig *configConnectivity, myErr error) {
	// 1. computes new set of external nodes (only type of nodes here) in cfg1 and cfg2
	// does so by computing disjoint block between src+dst ipBlocks in cfg1 and in cfg2
	// the new set of external nodes is determined based on them
	connectivityIPBlist, err := confConnectivity.connectivity.getIPBlocksList()
	if err != nil {
		return nil, nil, err
	}
	otherIPBlist, err := otherConfConnectivity.connectivity.getIPBlocksList()
	if err != nil {
		return nil, nil, err
	}
	disjointIPblocks := common.DisjointIPBlocks(connectivityIPBlist, otherIPBlist)
	// 2. copy configs and generates Nodes[] as per disjointIPblocks
	err = confConnectivity.config.refineConfigExternalNodes(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	alignedConfig := confConnectivity.config
	err = otherConfConnectivity.config.refineConfigExternalNodes(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	otherAlignedConfig := otherConfConnectivity.config
	// 3. resize connections as per the new Nodes[]
	alignedConnectivity, err := confConnectivity.connectivity.alignConnectionsGivenIPBlists(
		alignedConfig, disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	alignedOtherConnectivity, err := otherConfConnectivity.connectivity.alignConnectionsGivenIPBlists(
		otherAlignedConfig, disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	return &configConnectivity{alignedConfig, alignedConnectivity},
		&configConnectivity{otherAlignedConfig, alignedOtherConnectivity}, nil
}

func (connectivityMap *GeneralConnectivityMap) alignConnectionsGivenIPBlists(config *VPCConfig, disjointIPblocks []*common.IPBlock) (
	alignedConnectivity GeneralConnectivityMap, err error) {
	alignedConnectivitySrc, err := connectivityMap.actualAlignSrcOrDstGivenIPBlists(config, disjointIPblocks, true)
	if err != nil {
		return nil, err
	}
	alignedConnectivity, err = alignedConnectivitySrc.actualAlignSrcOrDstGivenIPBlists(config, disjointIPblocks, false)
	return alignedConnectivity, err
}

// aligned config: copies from old config everything but external nodes,
// external nodes are resized by disjointIPblocks
func (c *VPCConfig) refineConfigExternalNodes(disjointIPblocks []*common.IPBlock) error {
	// copy config
	var err error
	//  nodes - external addresses - are resized
	c.Nodes, err = resizeNodes(c.Nodes, disjointIPblocks)
	return err
}

func resizeNodes(oldNodes []Node, disjointIPblocks []*common.IPBlock) (newNodes []Node, err error) {
	newNodes = []Node{}
	//  range over old nodes and inside range over disjoint blocks
	//  if a disjoint block is contained in an old oldNode - create external oldNode and add it
	//  if no disjoint block is contained in an old oldNode - add the old oldNode as is
	for _, oldNode := range oldNodes {
		if oldNode.IsInternal() {
			newNodes = append(newNodes, oldNode)
			continue
		}
		nodeIPBlock, err := common.NewIPBlock(oldNode.Cidr(), nil)
		if err != nil {
			return nil, err
		}
		disjointContained := false
		for _, disjointIPBlock := range disjointIPblocks {
			if disjointIPBlock.ContainedIn(nodeIPBlock) {
				disjointContained = true
				for _, thisCidr := range disjointIPBlock.ToCidrList() {
					newNode := newExternalNodeForCidr(thisCidr)
					newNodes = append(newNodes, newNode)
				}
			}
		}
		if !disjointContained {
			newNodes = append(newNodes, oldNode)
		}
	}
	return newNodes, nil
}

func (connectivityMap *GeneralConnectivityMap) actualAlignSrcOrDstGivenIPBlists(config *VPCConfig,
	disjointIPblocks []*common.IPBlock, resizeSrc bool) (
	alignedConnectivity GeneralConnectivityMap, err error) {
	// goes over all sources of connections in connectivity
	// if src is external then for each IPBlock in disjointIPblocks copies dsts and connection type
	// otherwise just copies as is
	err = nil
	alignedConnectivity = map[VPCResourceIntf]map[VPCResourceIntf]*common.ConnectionSet{}
	for src, endpointConns := range *connectivityMap {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			// the resizing element is not external - copy as is
			if (resizeSrc && !src.IsExternal()) || (!resizeSrc && !dst.IsExternal()) {
				if _, ok := alignedConnectivity[src]; !ok {
					alignedConnectivity[src] = map[VPCResourceIntf]*common.ConnectionSet{}
				}
				alignedConnectivity[src][dst] = conns
				continue
			}
			// the resizing element is external - go over all ipBlock and allocates the connection
			// if the ipBlock is contained in the original src/dst
			var origIPBlock *common.IPBlock
			if resizeSrc {
				if node, ok := src.(Node); ok {
					origIPBlock, err = externalNodeToIPBlock(node)
				} else {
					return nil, fmt.Errorf(castingNodeErr, node.Name())
				}
			} else {
				if node, ok := dst.(Node); ok {
					origIPBlock, err = externalNodeToIPBlock(node)
				} else {
					return nil, fmt.Errorf(castingNodeErr, node.Name())
				}
			}
			if err != nil {
				return nil, err
			}
			err = addIPBlockToConnectivityMap(config, disjointIPblocks, origIPBlock, alignedConnectivity, src, dst, conns, resizeSrc)
		}
	}
	return alignedConnectivity, err
}

func addIPBlockToConnectivityMap(c *VPCConfig, disjointIPblocks []*common.IPBlock,
	origIPBlock *common.IPBlock, alignedConnectivity map[VPCResourceIntf]map[VPCResourceIntf]*common.ConnectionSet,
	src, dst VPCResourceIntf, conns *common.ConnectionSet, resizeSrc bool) error {
	for _, ipBlock := range disjointIPblocks {
		// get ipBlock of resized index (src/dst)
		if !ipBlock.ContainedIn(origIPBlock) { // ipBlock not relevant here
			continue
		}
		// origIPBlock has either several new disjointIPblocks contained in it or is contained in itself
		cidrList := ipBlock.ToCidrList()
		for _, cidr := range cidrList {
			nodeOfCidr := findNodeWithCidr(c.Nodes, cidr)
			if nodeOfCidr == nil {
				return fmt.Errorf("%s", fmt.Sprintf("A node with cidr %v not found in conf", cidr)) // should not get here
			}
			if resizeSrc {
				if _, ok := alignedConnectivity[nodeOfCidr]; !ok {
					alignedConnectivity[nodeOfCidr] = map[VPCResourceIntf]*common.ConnectionSet{}
				}
				alignedConnectivity[nodeOfCidr][dst] = conns
			} else {
				if _, ok := alignedConnectivity[src]; !ok {
					alignedConnectivity[src] = map[VPCResourceIntf]*common.ConnectionSet{}
				}
				alignedConnectivity[src][nodeOfCidr] = conns
			}
		}
	}
	return nil
}

// gets node with given cidr
func findNodeWithCidr(configNodes []Node, cidr string) Node {
	for _, node := range configNodes {
		if node.Cidr() == cidr {
			return node
		}
	}
	return nil
}

// get a list of IPBlocks of the src and dst of the connections
func (connectivityMap GeneralConnectivityMap) getIPBlocksList() (ipbList []*common.IPBlock,
	myErr error) {
	for src, endpointConns := range connectivityMap {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if src.IsExternal() {
				if srcNode, ok := src.(Node); ok {
					ipBlock, err := externalNodeToIPBlock(srcNode)
					if err != nil {
						return nil, err
					}
					ipbList = append(ipbList, ipBlock)
				} else {
					return nil, fmt.Errorf(castingNodeErr, src.Name())
				}
			}
			if dst.IsExternal() {
				if dstNode, ok := dst.(Node); ok {
					ipBlock, err := externalNodeToIPBlock(dstNode)
					if err != nil {
						return nil, err
					}
					ipbList = append(ipbList, ipBlock)
				} else {
					return nil, fmt.Errorf(castingNodeErr, dst.Name())
				}
			}
		}
	}
	return ipbList, nil
}

func externalNodeToIPBlock(external Node) (ipBlock *common.IPBlock, err error) {
	ipBlock, err = common.NewIPBlock(external.Cidr(), []string{})
	if err != nil {
		return nil, err
	}
	return ipBlock, nil
}

// todo: the following code finds all couples of connections that should be resized (it IPBlock)
// todo: it seems that the code is redundant; yet we keep it with its unit test in case we'll decide
// todo: to use it in the future
// todo: it return a string describing the intersecting connections for the unit test
// type ConnectionEnd struct {
//	 src EndpointElem
//	 dst EndpointElem
// }
// func (connectivity GeneralConnectivityMap) getIntersectingConnections(other GeneralConnectivityMap) (areIntersecting string,
//	err error) {
//	err = nil
//	for src, endpointConns := range connectivity {
//		for dst, conns := range endpointConns {
//			if (!src.IsExternal() && !dst.IsExternal()) || conns.IsEmpty() {
//				continue // nothing to do here
//			}
//			for otherSrc, otherEndpointConns := range other {
//				for otherDst, otherConns := range otherEndpointConns {
//					if otherConns.IsEmpty() {
//						continue
//					}
//					bothSrcExt := src.IsExternal() && otherSrc.IsExternal()
//					bothDstExt := dst.IsExternal() && otherDst.IsExternal()
//					if (!bothSrcExt && !bothDstExt) ||
//						otherConns.IsEmpty() {
//						continue // nothing to compare to here
//					}
//					myEp := &ConnectionEnd{src, dst}
//					otherEp := &ConnectionEnd{otherSrc, otherDst}
//					intersecting, err1 := myEp.connectionsIntersecting(otherEp)
//					if err1 != nil {
//						return areIntersecting, err1
//					}
//					if intersecting {
//						areIntersecting += fmt.Sprintf("<%v, %v> and <%v, %v> intersects\n", src.Name(), dst.Name(), otherSrc.Name(), otherDst.Name())
//					}
//				}
//			}
//		}
//	}
//	return areIntersecting, err
//}
//
//// two connections s.t. each contains at least one external end are comparable if either:
//// both src and dst in both connections are external and they both intersect
//// one end (src/dst) are external in both and intersects and the other (dst/src) are the same subnet
//// two connections s.t. each contains at least one external end are comparable if either:
//// both src and dst in both connections are external and they both intersect but not equal
//// or end (src/dst) are external in both and intersects and the other (dst/src) are the same subnet
// func (myConnEnd *ConnectionEnd) connectionsIntersecting(otherConnEnd *ConnectionEnd) (bool, error) {
//	srcComparable, err := pairEpsComparable(myConnEnd.src, otherConnEnd.src)
//	if err != nil {
//		return false, err
//	}
//	if !srcComparable {
//		return false, nil
//	}
//	dstComparable, err := pairEpsComparable(myConnEnd.dst, otherConnEnd.dst)
//	if err != nil {
//		return false, err
//	}
//	if !dstComparable {
//		return false, err
//	}
//	return true, nil
// }
//
//// checks if two eps refers to the same subnet or
//// refers to intersecting external addresses
// func pairEpsComparable(myEp, otherEp EndpointElem) (bool, error) {
//	mySubnet, isMySubnet := myEp.(NodeSet)
//	otherSubnet, isOtherSubnet := otherEp.(NodeSet)
//	myExternal, isMyExternal := myEp.(Node)
//	otherExternal, isOtherExternal := otherEp.(Node)
//	if (isMySubnet != isOtherSubnet) || (isMyExternal != isOtherExternal) {
//		return false, nil
//	}
//	if isMySubnet { // implies that isOtherSubnet as well
//		if mySubnet.Name() == otherSubnet.Name() {
//			return true, nil
//		}
//		return false, nil
//	}
//	// if we got here then both eps refer to external IP
//	myIPBlock, err := common.NewIPBlock(myExternal.Cidr(), []string{})
//	if err != nil {
//		return false, err
//	}
//	otherIPBlock, err := common.NewIPBlock(otherExternal.Cidr(), []string{})
//	if err != nil {
//		return false, err
//	}
//	if !myIPBlock.Equal(otherIPBlock) && !myIPBlock.Intersection(otherIPBlock).Empty() {
//		return true, nil
//	}
//	return false, nil
//}
//
//// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
////       encode the cfgsDiff into this generic item as well as the other entities we are grouping
////       and then decode in the printing
////       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
////       and also the diff where relevant
////       this will requires some rewriting in the existing grouping functionality and the way it provides
////       service to subnetsConnectivity and nodesConnectivity
//
// func (connectivity *GeneralConnectivityMap) PrintConnectivity() {
//	for src, endpointConns := range *connectivity {
//		for dst, conns := range endpointConns {
//			if conns.IsEmpty() {
//				continue
//			}
//			fmt.Printf("\t%v => %v %v\n", src.Name(), dst.Name(), conns.string())
//		}
//	}
// }
