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

const (
	castingNodeErr = "%s should be external node but casting to Node failed"
)

type connectionDiff struct {
	conn1 *common.ConnectionSet
	conn2 *common.ConnectionSet
	diff  DiffType
}

type SubnetsDiff map[VPCResourceIntf]map[VPCResourceIntf]*connectionDiff

type ConfigsForDiff struct {
	config1 *VPCConfig
	config2 *VPCConfig
}

type SubnetConfigConnectivity struct {
	config             *VPCConfig
	subnetConnectivity SubnetConnectivityMap
}

type DiffBetweenSubnets struct {
	subnet1Subtract2 SubnetsDiff
	subnet2Subtract1 SubnetsDiff
}

func (configs ConfigsForDiff) GetSubnetsDiff(grouping bool) (*DiffBetweenSubnets, error) {
	// 1. compute connectivity for each of the subnets
	subnetsConn1, err := configs.config1.GetSubnetsConnectivity(true, grouping)
	if err != nil {
		return nil, err
	}
	subnetsConn2, err := configs.config2.GetSubnetsConnectivity(true, grouping)
	if err != nil {
		return nil, err
	}

	// 2. Computes delta in both directions
	subnetConfigConn1 := &SubnetConfigConnectivity{configs.config1,
		subnetsConn1.AllowedConnsCombined}
	subnetConfigConn2 := &SubnetConfigConnectivity{configs.config2,
		subnetsConn2.AllowedConnsCombined}
	alignedConfigConnectivity1, alignedConfigConnectivity2, err :=
		subnetConfigConn1.getConnectivesWithSameIPBlocks(subnetConfigConn2)
	if err != nil {
		return nil, err
	}
	subnet1Subtract2, err1 := alignedConfigConnectivity1.subtract(alignedConfigConnectivity2, true)
	if err1 != nil {
		return nil, err1
	}
	subnet2Subtract1, err2 := alignedConfigConnectivity2.subtract(alignedConfigConnectivity1, false)
	if err2 != nil {
		return nil, err2
	}

	// 3. ToDo: grouping, see comment at the end of this file

	res := &DiffBetweenSubnets{
		subnet1Subtract2: subnet1Subtract2,
		subnet2Subtract1: subnet2Subtract1}
	return res, nil
}

// for a given VPCResourceIntf (representing a subnet or an external ip) in config return the VPCResourceIntf representing the
// subnet/external address in otherConfig or nil if the subnet does not exist in the other config.
func (c *VPCConfig) getVPCResourceInfInOtherConfig(other *VPCConfig, ep VPCResourceIntf) (res VPCResourceIntf, err error) {
	if ep.IsExternal() {
		var node Node
		var ok bool
		if node, ok = ep.(Node); ok {
			nodeSameCidr := findNodeWithCidr(other.Nodes, ep.(Node).Cidr())
			return nodeSameCidr, nil
		}
		return nil, fmt.Errorf(castingNodeErr, node.Name())
	}
	for _, nodeSet := range other.NodeSets {
		if nodeSet.Name() == ep.Name() {
			res = VPCResourceIntf(nodeSet)
			return res, nil
		}
	}
	return nil, nil
}

// subtract Subtract one SubnetConnectivityMap from the other:
// connections may be identical, non-existing in other or existing in other but changed;
// the latter are included only if includeChanged, to avoid duplication in the final presentation
//
// assumption: any connection from connectivity and "other" have src (dst) which are either disjoint or equal
func (subnetConfConnectivity *SubnetConfigConnectivity) subtract(other *SubnetConfigConnectivity, includeChanged bool) (
	connectivitySubtract SubnetsDiff, err error) {
	connectivitySubtract = map[VPCResourceIntf]map[VPCResourceIntf]*connectionDiff{}
	for src, endpointConns := range subnetConfConnectivity.subnetConnectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if _, ok := connectivitySubtract[src]; !ok {
				connectivitySubtract[src] = map[VPCResourceIntf]*connectionDiff{}
			}
			srcInOther, err1 := subnetConfConnectivity.config.getVPCResourceInfInOtherConfig(other.config, src)
			if err1 != nil {
				return nil, err1
			}
			dstInOther, err2 := subnetConfConnectivity.config.getVPCResourceInfInOtherConfig(other.config, dst)
			if err2 != nil {
				return nil, err2
			}
			connDiff := &connectionDiff{conns, nil, missingConnection}
			if srcInOther != nil && dstInOther != nil {
				if otherSrc, ok := other.subnetConnectivity[srcInOther]; ok {
					if otherConn, ok := otherSrc[dstInOther]; ok {
						// ToDo: https://github.com/np-guard/vpc-network-config-analyzer/issues/199
						if !includeChanged || conns.Equal(otherConn) {
							continue
						}
						connDiff.conn2 = otherConn
						connDiff.diff = changedConnection
					}
				}
			} else { // srcInOther == nil || dstInOther == nil
				connDiff.diff = getDiffType(src, srcInOther, dst, dstInOther)
			}
			connectivitySubtract[src][dst] = connDiff
		}
	}
	return connectivitySubtract, nil
}

// lack of a subnet is marked as a missing endpoint
// a lack of identical external endpoint is considered as a missing connection
// and not as a missing endpoint
func getDiffType(src, srcInOther, dst, dstInOther VPCResourceIntf) DiffType {
	_, srcIsSubnet := src.(NodeSet)
	_, dstIsSubnet := dst.(NodeSet)
	missingSrc := srcInOther == nil && srcIsSubnet
	missingDst := dstInOther == nil && dstIsSubnet
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

// EnhancedString ToDo: likely the current printing functionality will no longer be needed once the grouping is added
// anyways the diff print will be worked on before the final merge

func (diff *DiffBetweenSubnets) String() string {
	return diff.subnet1Subtract2.EnhancedString(true) + "\n" +
		diff.subnet2Subtract1.EnhancedString(false)
}

func (subnetDiff *SubnetsDiff) EnhancedString(thisMinusOther bool) string {
	strList := []string{}
	for src, endpointConnDiff := range *subnetDiff {
		for dst, connDiff := range endpointConnDiff {
			conn1Str, conn2Str := "", ""
			if thisMinusOther {
				conn1Str = connStr(connDiff.conn1)
				conn2Str = connStr(connDiff.conn2)
			} else {
				conn1Str = connStr(connDiff.conn2)
				conn2Str = connStr(connDiff.conn1)
			}
			diffType, endpointsDiff := diffAndEndpointsDisc(connDiff.diff, src, dst, thisMinusOther)
			printDiff := fmt.Sprintf("diff-type: %s, source: %s, destination: %s, config1: %s, config2: %s%s\n",
				diffType, src.Name(), dst.Name(), conn1Str, conn2Str, endpointsDiff)
			strList = append(strList, printDiff)
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}

// prints connection for func (subnetDiff *SubnetsDiff) EnhancedString(..) where the connection could be empty
func connStr(conn *common.ConnectionSet) string {
	if conn == nil {
		return "No connection"
	}
	return conn.EnhancedString()
}

func diffAndEndpointsDisc(diff DiffType, src, dst VPCResourceIntf, thisMinusOther bool) (diffDisc, workLoad string) {
	const (
		subnetsDiffInfo = ", subnets-diff-info:"
		tripleString    = "%s %s %s"
	)
	addOrRemoved := ""
	if thisMinusOther {
		addOrRemoved = "added"
	} else {
		addOrRemoved = "removed"
	}
	switch diff {
	case missingSrcEP:
		return addOrRemoved, fmt.Sprintf(tripleString, subnetsDiffInfo, src.Name(), addOrRemoved)
	case missingDstEP:
		return addOrRemoved, fmt.Sprintf(tripleString, subnetsDiffInfo, dst.Name(), addOrRemoved)
	case missingSrcDstEP:
		return addOrRemoved, fmt.Sprintf("%s %s and %s %s",
			subnetsDiffInfo, src.Name(), dst.Name(), addOrRemoved)
	case missingConnection:
		return addOrRemoved, ""
	case changedConnection:
		return "changed", ""
	}
	return "", ""
}

// getConnectivesWithSameIPBlocks generates from subnet1Connectivity.AllowedConnsCombined and subnet2Connectivity.AllowedConnsCombined
// Two equivalent SubnetConnectivityMap objects s.t. any (src1, dst1) of subnet1Connectivity and
// (src2, dst2) of subnet2Connectivity s.t. if src1 and src2 (dst1 and dst2) are both external then
// they are either equal or disjoint
func (subnetConfConnectivity *SubnetConfigConnectivity) getConnectivesWithSameIPBlocks(otherConfConnectivity *SubnetConfigConnectivity) (
	alignedConnectivityConfig, alignedOtherConnectivityConfig *SubnetConfigConnectivity, myErr error) {
	// 1. computes new set of external nodes (only type of nodes here) in cfg1 and cfg2
	// does so by computing disjoint block between src+dst ipBlocks in cfg1 and in cfg2
	// the new set of external nodes is determined based on them
	connectivityIPBlist, err := subnetConfConnectivity.subnetConnectivity.getIPBlocksList()
	if err != nil {
		return nil, nil, err
	}
	otherIPBlist, err := otherConfConnectivity.subnetConnectivity.getIPBlocksList()
	if err != nil {
		return nil, nil, err
	}
	disjointIPblocks := common.DisjointIPBlocks(connectivityIPBlist, otherIPBlist)
	// 2. copy configs and generates Nodes[] as per disjointIPblocks
	err = subnetConfConnectivity.config.refineConfigExternalNodes(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	alignedConfig := subnetConfConnectivity.config
	err = otherConfConnectivity.config.refineConfigExternalNodes(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	otherAlignedConfig := otherConfConnectivity.config
	// 3. resize connections as per the new Nodes[]
	alignedConnectivity, err := subnetConfConnectivity.subnetConnectivity.alignConnectionsGivenIPBlists(
		alignedConfig, disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	alignedOtherConnectivity, err := otherConfConnectivity.subnetConnectivity.alignConnectionsGivenIPBlists(
		otherAlignedConfig, disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	return &SubnetConfigConnectivity{alignedConfig, alignedConnectivity},
		&SubnetConfigConnectivity{otherAlignedConfig, alignedOtherConnectivity}, nil
}

func (subnetConnectivity *SubnetConnectivityMap) alignConnectionsGivenIPBlists(config *VPCConfig, disjointIPblocks []*common.IPBlock) (
	alignedConnectivity SubnetConnectivityMap, err error) {
	alignedConnectivitySrc, err := subnetConnectivity.actualAlignSrcOrDstGivenIPBlists(config, disjointIPblocks, true)
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

func (subnetConnectivity *SubnetConnectivityMap) actualAlignSrcOrDstGivenIPBlists(config *VPCConfig,
	disjointIPblocks []*common.IPBlock, resizeSrc bool) (
	alignedConnectivity SubnetConnectivityMap, err error) {
	// goes over all sources of connections in connectivity
	// if src is external then for each IPBlock in disjointIPblocks copies dsts and connection type
	// otherwise just copies as is
	err = nil
	alignedConnectivity = map[VPCResourceIntf]map[VPCResourceIntf]*common.ConnectionSet{}
	for src, endpointConns := range *subnetConnectivity {
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
func (subnetConnectivity SubnetConnectivityMap) getIPBlocksList() (ipbList []*common.IPBlock,
	myErr error) {
	for src, endpointConns := range subnetConnectivity {
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
// func (subnetConnectivity SubnetConnectivityMap) getIntersectingConnections(other SubnetConnectivityMap) (areIntersecting string,
//	err error) {
//	err = nil
//	for src, endpointConns := range subnetConnectivity {
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
////       encode the subnetsDiff into this generic item as well as the other entities we are grouping
////       and then decode in the printing
////       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
////       and also the diff where relevant
////       this will requires some rewriting in the existing grouping functionality and the way it provides
////       service to subnetsConnectivity and nodesConnectivity
//
// func (subnetConnectivity *SubnetConnectivityMap) PrintConnectivity() {
//	for src, endpointConns := range *subnetConnectivity {
//		for dst, conns := range endpointConns {
//			if conns.IsEmpty() {
//				continue
//			}
//			fmt.Printf("\t%v => %v %v\n", src.Name(), dst.Name(), conns.EnhancedString())
//		}
//	}
// }
