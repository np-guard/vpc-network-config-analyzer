/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
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
	configsStr     = "config1: %s, config2: %s%s"
	semicolon      = ";"
)

type connectionDiff struct {
	conn1          *detailedConn
	conn2          *detailedConn
	diff           DiffType
	thisMinusOther bool
}

type connectivityDiff map[VPCResourceIntf]map[VPCResourceIntf]*connectionDiff

type configsForDiff struct {
	config1      *VPCConfig
	config2      *VPCConfig
	diffAnalysis diffAnalysisType
}

type configConnectivity struct {
	config       *VPCConfig
	connectivity GeneralResponsiveConnectivityMap
}

type diffBetweenCfgs struct {
	diffAnalysis diffAnalysisType

	cfg1ConnRemovedFrom2 connectivityDiff
	cfg2ConnRemovedFrom1 connectivityDiff

	// grouped connectivity result
	groupedLines []*groupedConnLine
}

// GetDiff given 2 *VPCConfigs and an diff analysis - either subnets or endpoints -
// computes and returns the semantic diff of endpoints or subnets connectivity, as per the required analysis
func (configs configsForDiff) GetDiff() (*diffBetweenCfgs, error) {
	// 1. compute connectivity for each of the configurations
	responsiveConnectivityMap1, err := configs.config1.getAllowedResponsiveConnections(configs.diffAnalysis)
	if err != nil {
		return nil, err
	}
	responsiveConnectivityMap2, err := configs.config2.getAllowedResponsiveConnections(configs.diffAnalysis)
	if err != nil {
		return nil, err
	}

	// 2. Computes delta in both directions
	configConn1 := &configConnectivity{configs.config1,
		responsiveConnectivityMap1}
	configConn2 := &configConnectivity{configs.config2,
		responsiveConnectivityMap2}
	alignedConfigConnectivity1, alignedConfigConnectivity2, err :=
		configConn1.getConnectivityWithSameIPBlocks(configConn2)
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

func (c *VPCConfig) getAllowedResponsiveConnections(
	diffAnalysis diffAnalysisType) (responsiveConnectivityMap GeneralResponsiveConnectivityMap, err error) {
	if diffAnalysis == Subnets {
		subnetsConn, err := c.GetSubnetsConnectivity(true, false)
		if err != nil {
			return nil, err
		}
		return subnetsConn.AllowedConnsCombinedResponsive, err
	} else if diffAnalysis == Vsis {
		connectivity1, err := c.GetVPCNetworkConnectivity(false, false)
		if err != nil {
			return nil, err
		}
		return connectivity1.AllowedConnsCombinedResponsive, nil
	}
	return nil, fmt.Errorf("illegal diff analysis type")
}

// for a given VPCResourceIntf (representing a subnet or an external ip) in config return the VPCResourceIntf representing the
// subnet/external address in otherConfig or nil if the subnet does not exist in the other config.
func (c *VPCConfig) getVPCResourceInfInOtherConfig(other *VPCConfig, ep VPCResourceIntf,
	diffAnalysis diffAnalysisType) (res VPCResourceIntf, err error) {
	if ep.IsExternal() {
		if node, ok := ep.(*ExternalNetwork); ok {
			nodeSameCidr := findNodeWithCidr(other.Nodes, node.CidrStr)
			return nodeSameCidr, nil
		}
		return nil, fmt.Errorf(castingNodeErr, ep.NameForAnalyzerOut(nil))
	}
	// endpoint is a vsi or a subnet, depending on diffAnalysis value
	if diffAnalysis == Vsis {
		for _, node := range other.Nodes {
			if !node.IsInternal() {
				continue
			}
			if node.NameForAnalyzerOut(nil) == ep.NameForAnalyzerOut(nil) {
				res = VPCResourceIntf(node)
				return res, nil
			}
		}
	} else if diffAnalysis == Subnets {
		for _, subnet := range other.Subnets {
			if subnet.NameForAnalyzerOut(nil) == ep.NameForAnalyzerOut(nil) {
				res = VPCResourceIntf(subnet)
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
		for dst, conn := range endpointConns {
			if conn.isEmpty() {
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
			// includeChanged indicates if it is thisMinusOther
			connDiff := &connectionDiff{
				conn1:          conn,
				conn2:          emptyDetailedConn(),
				diff:           missingConnection,
				thisMinusOther: includeChanged,
			}
			if srcInOther != nil && dstInOther != nil {
				if otherSrc, ok := other.connectivity[srcInOther]; ok {
					if otherConn, ok := otherSrc[dstInOther]; ok {
						if !includeChanged || conn.equal(otherConn) {
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

func getDiffInfoHeader(diffAnalysis diffAnalysisType) string {
	if diffAnalysis == Subnets {
		return "subnets-diff-info:"
	} else if diffAnalysis == Vsis {
		return "vsis-diff-info:"
	}
	return ""
}

func conn1And2Str(connDiff *connectionDiff) (conn1Str, conn2Str string) {
	if connDiff.thisMinusOther {
		conn1Str = connStr(connDiff.conn1)
		conn2Str = connStr(connDiff.conn2)
	} else {
		conn1Str = connStr(connDiff.conn2)
		conn2Str = connStr(connDiff.conn1)
	}
	return conn1Str, conn2Str
}

// printGroupedDiffLine print one grouped diff line
func printGroupedDiffLine(diffAnalysis diffAnalysisType, src, dst EndpointElem, commonProps *groupedCommonProperties) string {
	diffType, diffInfoBody := diffAndEndpointsDescription(commonProps.connDiff.diff, src, dst, commonProps.connDiff.thisMinusOther)
	conn1Str, conn2Str := conn1And2Str(commonProps.connDiff)
	diffTypeStr := fmt.Sprintf("%v %s", diffTypeStr, diffType)
	diffInfo := getDiffInfo(diffAnalysis, diffInfoBody)
	connDiffStr := fmt.Sprintf(configsStr, conn1Str, conn2Str, diffInfo)
	printDiff := fmt.Sprintf("%s, source: %s, destination: %s, %s\n", diffTypeStr,
		src.NameForAnalyzerOut(nil), dst.NameForAnalyzerOut(nil), connDiffStr)
	return printDiff
}

func getDiffInfo(diffAnalysis diffAnalysisType, diffInfoBody string) string {
	if diffInfoBody == "" {
		return ""
	}
	diffInfoHeader := getDiffInfoHeader(diffAnalysis)
	return ", " + diffInfoHeader + " " + diffInfoBody
}

func (diffCfgs *diffBetweenCfgs) String() string {
	strList := make([]string, len(diffCfgs.groupedLines))
	for i, grouped := range diffCfgs.groupedLines {
		strList[i] = printGroupedDiffLine(diffCfgs.diffAnalysis, grouped.Src, grouped.Dst, grouped.CommonProperties)
	}
	sort.Strings(strList)
	return strings.Join(strList, "")
}

// get the grouped diff connectivity stateLessness
func (diffCfgs *diffBetweenCfgs) hasStatelessConns() bool {
	hasStatelessConns := false
	for _, grouped := range diffCfgs.groupedLines {
		if (grouped.CommonProperties.connDiff.conn1 != nil &&
			!grouped.CommonProperties.connDiff.conn1.TCPRspDisable.IsEmpty()) ||
			(grouped.CommonProperties.connDiff.conn2 != nil &&
				!grouped.CommonProperties.connDiff.conn2.TCPRspDisable.IsEmpty()) {
			hasStatelessConns = true
			break
		}
	}
	return hasStatelessConns
}

// prints connection for the above string(..) where the connection could be empty
func connStr(extConn *detailedConn) string {
	if extConn == nil {
		return connection.NoConnections
	}
	return extConn.string()
}

func diffAndEndpointsDescription(diff DiffType, src, dst EndpointElem, thisMinusOther bool) (diffDesc, workLoad string) {
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
		return addOrRemoved, fmt.Sprintf(doubleString, src.NameForAnalyzerOut(nil), addOrRemoved)
	case missingDstEP:
		return addOrRemoved, fmt.Sprintf(doubleString, dst.NameForAnalyzerOut(nil), addOrRemoved)
	case missingSrcDstEP:
		return addOrRemoved, fmt.Sprintf("%s and %s %s",
			src.NameForAnalyzerOut(nil), dst.NameForAnalyzerOut(nil), addOrRemoved)
	case missingConnection:
		return addOrRemoved, ""
	case changedConnection:
		return "changed", ""
	}
	return "", ""
}

// getConnectivityWithSameIPBlocks generates from the given GeneralConnectivityMap
// Two equivalent GeneralConnectivityMap objects s.t. any (src1, dst1) of the first map and
// (src2, dst2) of the 2nd map s.t. if src1 and src2 (dst1 and dst2) are both external then
// they are either equal or disjoint
func (confConnectivity *configConnectivity) getConnectivityWithSameIPBlocks(otherConfConnectivity *configConnectivity) (
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
	disjointIPblocks := ipblock.DisjointIPBlocks(connectivityIPBlist, otherIPBlist)
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

func (responsiveConnMap *GeneralResponsiveConnectivityMap) alignConnectionsGivenIPBlists(config *VPCConfig,
	disjointIPblocks []*ipblock.IPBlock) (
	alignedConnectivity GeneralResponsiveConnectivityMap, err error) {
	alignedConnectivitySrc, err := responsiveConnMap.actualAlignSrcOrDstGivenIPBlists(config, disjointIPblocks, true)
	if err != nil {
		return nil, err
	}
	alignedConnectivity, err = alignedConnectivitySrc.actualAlignSrcOrDstGivenIPBlists(config, disjointIPblocks, false)
	return alignedConnectivity, err
}

// aligned config: copies from old config everything but external nodes,
// external nodes are resized by disjointIPblocks
func (c *VPCConfig) refineConfigExternalNodes(disjointIPblocks []*ipblock.IPBlock) error {
	// copy config
	var err error
	//  nodes - external addresses - are resized
	c.Nodes, err = resizeNodes(c.Nodes, disjointIPblocks)
	return err
}

func resizeNodes(oldNodes []Node, disjointIPblocks []*ipblock.IPBlock) (newNodes []Node, err error) {
	newNodes = []Node{}
	//  range over old nodes and inside range over disjoint blocks
	//  if a disjoint block is contained in an old oldNode - create external oldNode and add it
	//  if no disjoint block is contained in an old oldNode - add the old oldNode as is
	for _, oldNode := range oldNodes {
		if oldNode.IsInternal() {
			newNodes = append(newNodes, oldNode)
			continue
		}
		disjointContained := false
		for _, disjointIPBlock := range disjointIPblocks {
			if disjointIPBlock.ContainedIn(oldNode.IPBlock()) {
				disjointContained = true
				for _, thisCidr := range disjointIPBlock.ToCidrList() {
					newNode, err := newExternalNodeForCidr(thisCidr)
					if err != nil {
						return nil, err
					}
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

func (responsiveConnMap *GeneralResponsiveConnectivityMap) actualAlignSrcOrDstGivenIPBlists(config *VPCConfig,
	disjointIPblocks []*ipblock.IPBlock, resizeSrc bool) (
	alignedConnectivity GeneralResponsiveConnectivityMap, err error) {
	// goes over all sources of connections in connectivity
	// if src is external then for each IPBlock in disjointIPblocks copies dsts and connection type
	// otherwise just copies as is
	err = nil
	alignedConnectivity = map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn{}
	for src, endpointConns := range *responsiveConnMap {
		for dst, connsWithResponsive := range endpointConns {
			if connsWithResponsive.isEmpty() {
				continue
			}
			// the resizing element is not external - copy as is
			if (resizeSrc && !src.IsExternal()) || (!resizeSrc && !dst.IsExternal()) {
				if _, ok := alignedConnectivity[src]; !ok {
					alignedConnectivity[src] = map[VPCResourceIntf]*detailedConn{}
				}
				alignedConnectivity[src][dst] = connsWithResponsive
				continue
			}
			// the resizing element is external - go over all ipBlock and allocates the connection
			// if the ipBlock is contained in the original src/dst
			var origIPBlock *ipblock.IPBlock
			if resizeSrc {
				if node, ok := src.(Node); ok {
					origIPBlock = node.IPBlock()
				} else {
					return nil, fmt.Errorf(castingNodeErr, node.NameForAnalyzerOut(nil))
				}
			} else {
				if node, ok := dst.(Node); ok {
					origIPBlock = node.IPBlock()
				} else {
					return nil, fmt.Errorf(castingNodeErr, node.NameForAnalyzerOut(nil))
				}
			}
			if err != nil {
				return nil, err
			}
			err = addIPBlockToConnectivityMap(config, disjointIPblocks, origIPBlock, alignedConnectivity, src, dst, connsWithResponsive, resizeSrc)
		}
	}
	return alignedConnectivity, err
}

func addIPBlockToConnectivityMap(c *VPCConfig, disjointIPblocks []*ipblock.IPBlock,
	origIPBlock *ipblock.IPBlock, alignedConnectivity map[VPCResourceIntf]map[VPCResourceIntf]*detailedConn,
	src, dst VPCResourceIntf, conns *detailedConn, resizeSrc bool) error {
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
					alignedConnectivity[nodeOfCidr] = map[VPCResourceIntf]*detailedConn{}
				}
				alignedConnectivity[nodeOfCidr][dst] = conns
			} else {
				if _, ok := alignedConnectivity[src]; !ok {
					alignedConnectivity[src] = map[VPCResourceIntf]*detailedConn{}
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
		if node.CidrOrAddress() == cidr {
			return node
		}
	}
	return nil
}

// get a list of IPBlocks of the src and dst of the connections
func (responsiveConnMap GeneralResponsiveConnectivityMap) getIPBlocksList() (ipbList []*ipblock.IPBlock,
	myErr error) {
	for src, endpointConns := range responsiveConnMap {
		for dst, connsWithStateful := range endpointConns {
			if connsWithStateful.isEmpty() {
				continue
			}
			if src.IsExternal() {
				if srcNode, ok := src.(Node); ok {
					ipbList = append(ipbList, srcNode.IPBlock())
				} else {
					return nil, fmt.Errorf(castingNodeErr, src.NameForAnalyzerOut(nil))
				}
			}
			if dst.IsExternal() {
				if dstNode, ok := dst.(Node); ok {
					ipbList = append(ipbList, dstNode.IPBlock())
				} else {
					return nil, fmt.Errorf(castingNodeErr, dst.NameForAnalyzerOut(nil))
				}
			}
		}
	}
	return ipbList, nil
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
//			if (!src.IsExternal() && !dst.IsExternal()) || conns.isEmpty() {
//				continue // nothing to do here
//			}
//			for otherSrc, otherEndpointConns := range other {
//				for otherDst, otherConns := range otherEndpointConns {
//					if otherConns.isEmpty() {
//						continue
//					}
//					bothSrcExt := src.IsExternal() && otherSrc.IsExternal()
//					bothDstExt := dst.IsExternal() && otherDst.IsExternal()
//					if (!bothSrcExt && !bothDstExt) ||
//						otherConns.isEmpty() {
//						continue // nothing to compare to here
//					}
//					myEp := &ConnectionEnd{src, dst}
//					otherEp := &ConnectionEnd{otherSrc, otherDst}
//					intersecting, err1 := myEp.connectionsIntersecting(otherEp)
//					if err1 != nil {
//						return areIntersecting, err1
//					}
//					if intersecting {
//						areIntersecting += fmt.Sprintf("<%v, %v> and <%v, %v> intersects\n", src.NameForAnalyzerOut(nil),
//							dst.NameForAnalyzerOut(nil), otherSrc.NameForAnalyzerOut(nil), otherDst.NameForAnalyzerOut(nil))
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
//		if mySubnet.NameForAnalyzerOut(nil) == otherSubnet.NameForAnalyzerOut(nil) {
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
//	if !myIPBlock.Equal(otherIPBlock) && !myIPBlock.intersect(otherIPBlock).Empty() {
//		return true, nil
//	}
//	return false, nil
//}
//
//// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
////       encode the cfgsDiff into this generic item as well as the other entities we are grouping
////       and then decode in the printing
////       the idea is to use instead of *connection.Set in the grouped entity a string which will encode the connection
////       and also the diff where relevant
////       this will requires some rewriting in the existing grouping functionality and the way it provides
////       service to subnetsConnectivity and nodesConnectivity
//
// func (connectivity *GeneralConnectivityMap) PrintConnectivity() {
//	for src, endpointConns := range *connectivity {
//		for dst, conns := range endpointConns {
//			if conns.isEmpty() {
//				continue
//			}
//			fmt.Printf("\t%v => %v %v\n", src.NameForAnalyzerOut(nil), dst.NameForAnalyzerOut(nil), conns.string())
//		}
//	}
// }
