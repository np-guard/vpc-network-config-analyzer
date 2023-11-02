package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

type DiffType = int

const (
	NoDiff DiffType = iota
	MissingSrcEP
	MissingDstEP
	MissingSrcDstEP
	MissingConnection
	ChangedConnection
)

type connectionDiff struct {
	*common.ConnectionSet
	diff DiffType
}

type SubnetsDiff map[EndpointElem]map[EndpointElem]*connectionDiff

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

	GroupedSubnet1Minus2 *GroupConnLines
	GroupedSubnet1Minus1 *GroupConnLines
}

func (configs ConfigsForDiff) GetSubnetsDiff(grouping bool) (*DiffBetweenSubnets, error) {
	// 1. compute connectivity for each of the subnets
	subnetsConn1, err := configs.config1.GetSubnetsConnectivity(true, false)
	if err != nil {
		return nil, err
	}
	subnetsConn2, err := configs.config2.GetSubnetsConnectivity(true, false)
	if err != nil {
		return nil, err
	}

	// 2. Computes delta in both directions
	subnetConfigConn1 := &SubnetConfigConnectivity{configs.config1,
		subnetsConn1.AllowedConnsCombined}
	subnetConfigConn2 := &SubnetConfigConnectivity{configs.config2,
		subnetsConn2.AllowedConnsCombined}
	alignedConfigConnectivity1, alignedConfigConnectivity2, err :=
		subnetConfigConn1.GetConnectivesWithSameIPBlocks(subnetConfigConn2)
	if err != nil {
		return nil, err
	}
	subnet1Subtract2 := alignedConfigConnectivity1.SubnetConnectivitySubtract(alignedConfigConnectivity2)
	subnet2Subtract1 := alignedConfigConnectivity2.SubnetConnectivitySubtract(alignedConfigConnectivity1)

	// 3. ToDo: grouping, see comment at the end of this file

	res := &DiffBetweenSubnets{
		subnet1Subtract2: subnet1Subtract2,
		subnet2Subtract1: subnet2Subtract1}
	return res, nil
}

// for a given EndpointElem (representing a subnet or an external ip) in config return the EndpointElem representing the
// subnet/external address in otherConfig or nil if the subnet does not exist in the other config.
func (c *VPCConfig) getEndpointElemInOtherConfig(other *VPCConfig, ep EndpointElem) EndpointElem {
	if ep.IsExternal() {
		nodeSameCidr, _ := findNodeWithCidr(other.Nodes, ep.(Node).Cidr())
		return nodeSameCidr
	}
	for _, nodeSet := range other.NodeSets {
		if nodeSet.Name() == ep.Name() {
			res := EndpointElem(nodeSet)
			return res
		}
	}
	return nil
}

// SubnetConnectivitySubtract Subtract one SubnetConnectivityMap from the other
// assumption: any connection from connectivity and "other" have src (dst) which are either disjoint or equal
func (subnetConfConnectivity *SubnetConfigConnectivity) SubnetConnectivitySubtract(other *SubnetConfigConnectivity) SubnetsDiff {
	connectivitySubtract := map[EndpointElem]map[EndpointElem]*connectionDiff{}
	for src, endpointConns := range subnetConfConnectivity.subnetConnectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if _, ok := connectivitySubtract[src]; !ok {
				connectivitySubtract[src] = map[EndpointElem]*connectionDiff{}
			}
			diffConnectionWithType := &connectionDiff{nil, NoDiff}
			srcInOther := subnetConfConnectivity.config.getEndpointElemInOtherConfig(other.config, src)
			dstInOther := subnetConfConnectivity.config.getEndpointElemInOtherConfig(other.config, dst)
			if srcInOther != nil && dstInOther != nil {
				if otherSrc, ok := other.subnetConnectivity[srcInOther]; ok {
					if otherSrcDst, ok := otherSrc[dstInOther]; ok {
						// ToDo: https://github.com/np-guard/vpc-network-config-analyzer/issues/199
						subtractConn := conns.Subtract(otherSrcDst)
						if subtractConn.IsEmpty() {
							continue // no diff
						}
						diffConnectionWithType.ConnectionSet = subtractConn
						diffConnectionWithType.diff = ChangedConnection
					}
				}
				if diffConnectionWithType.diff != ChangedConnection {
					diffConnectionWithType.diff = MissingConnection
				}
			} else { // srcInOther == nil || dstInOther == nil
				diffConnectionWithType.diff = getDiffType(src, srcInOther, dst, dstInOther)
			}
			connectivitySubtract[src][dst] = diffConnectionWithType
		}
	}
	return connectivitySubtract
}

// lack of a subnet is marked as a missing endpoint
// a lack of identical external endpoint is considered as a missing connection
// and not as a missing endpoint
func getDiffType(src, srcInOther, dst, dstInOther EndpointElem) DiffType {
	_, srcIsSubnet := src.(NodeSet)
	_, dstIsSubnet := dst.(NodeSet)
	missingSrc := srcInOther == nil && srcIsSubnet
	missingDst := dstInOther == nil && dstIsSubnet
	switch {
	case missingSrc && missingDst:
		return MissingSrcDstEP
	case missingSrc:
		return MissingSrcEP
	case missingDst:
		return MissingDstEP
	case srcInOther == nil || dstInOther == nil:
		return MissingConnection
	}
	return NoDiff
}

// EnhancedString ToDo: likely the current printing functionality will no longer be needed once the grouping is added
// anyways the diff print will be worked on before the final merge

func (diff *DiffBetweenSubnets) String() string {
	return diff.subnet1Subtract2.EnhancedString(true) + "\n" +
		diff.subnet2Subtract1.EnhancedString(false)
}

func (subnetDiff *SubnetsDiff) EnhancedString(thisMinusOther bool) string {
	var diffDirection, printDiff string
	if thisMinusOther {
		diffDirection = "--"
	} else {
		diffDirection = "++"
	}
	for src, endpointConnDiff := range *subnetDiff {
		for dst, connDiff := range endpointConnDiff {
			var connectionSetDiff string
			if connDiff.ConnectionSet != nil {
				connectionSetDiff = connDiff.ConnectionSet.EnhancedString()
			}
			printDiff += fmt.Sprintf("%s %s => %s : %s %s\n", diffDirection, src.Name(), dst.Name(),
				diffDescription(connDiff.diff), connectionSetDiff)
		}
	}
	return printDiff
}

func diffDescription(diff DiffType) string {
	switch diff {
	case MissingSrcEP:
		return "missing source"
	case MissingDstEP:
		return "missing destination"
	case MissingSrcDstEP:
		return "missing source and destination"
	case MissingConnection:
		return "missing connection"
	case ChangedConnection:
		return "changed connection"
	}
	return ""
}

// GetConnectivesWithSameIPBlocks generates from subnet1Connectivity.AllowedConnsCombined and subnet2Connectivity.AllowedConnsCombined
// Two equivalent SubnetConnectivityMap objects s.t. any (src1, dst1) of subnet1Connectivity and
// (src2, dst2) of subnet2Connectivity s.t. if src1 and src2 (dst1 and dst2) are both external then
// they are either equal or disjoint
func (subnetConfConnectivity *SubnetConfigConnectivity) GetConnectivesWithSameIPBlocks(otherConfConnectivity *SubnetConfigConnectivity) (
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
	alignedConfig, err := subnetConfConnectivity.config.copyConfig(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
	otherAlignedConfig, err := otherConfConnectivity.config.copyConfig(disjointIPblocks)
	if err != nil {
		return nil, nil, err
	}
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
		&SubnetConfigConnectivity{otherAlignedConfig, alignedOtherConnectivity}, myErr
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

// aligned config: copies from old config everything but nodes,
// nodes are resized by disjointIPblocks
func (c *VPCConfig) copyConfig(disjointIPblocks []*common.IPBlock) (alignedConfig *VPCConfig, err error) {
	// copy config
	alignedConfig = c
	//  nodes - external addresses - are resized
	alignedConfig.Nodes, err = resizeNodes(c.Nodes, disjointIPblocks)
	return alignedConfig, err
}

func resizeNodes(oldNodes []Node, disjointIPblocks []*common.IPBlock) (newNodes []Node, err error) {
	newNodes = []Node{}
	//  range over old nodes and inside range over disjoint blocks
	//  if a disjoint block is contained in an old oldNode - create external oldNode and add it
	//  if no disjoint block is contained in an old oldNode - add the old oldNode as is
	for _, oldNode := range oldNodes {
		nodeIPBlock, err := common.NewIPBlock(oldNode.Cidr(), nil)
		if err != nil {
			return nil, err
		}
		disjointContained := false
		for _, disjointIPBlock := range disjointIPblocks {
			if disjointIPBlock.ContainedIn(nodeIPBlock) {
				disjointContained = true
				for _, thisCidr := range disjointIPBlock.ToCidrList() {
					newNode := NewExternalNodeForCidr(thisCidr)
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
	alignedConnectivity = map[EndpointElem]map[EndpointElem]*common.ConnectionSet{}
	for src, endpointConns := range *subnetConnectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if _, ok := alignedConnectivity[src]; !ok {
				alignedConnectivity[src] = map[EndpointElem]*common.ConnectionSet{}
			}
			// the resizing element is not external - copy as is
			if (resizeSrc && !src.IsExternal()) || (!resizeSrc && !dst.IsExternal()) {
				alignedConnectivity[src][dst] = conns
				continue
			}
			// the resizing element is external - go over all ipBlock and allocates the connection
			// if the ipBlock is contained in the original src/dst
			var origIPBlock *common.IPBlock
			if resizeSrc {
				origIPBlock, err = externalNodeToIPBlock(src.(Node))
			} else {
				origIPBlock, err = externalNodeToIPBlock(dst.(Node))
			}
			if err != nil {
				return nil, err
			}
			err = config.addIPBlockToConnectivityMap(disjointIPblocks, origIPBlock, alignedConnectivity, src, dst, conns, resizeSrc)
		}
	}
	return alignedConnectivity, err
}

func (c *VPCConfig) addIPBlockToConnectivityMap(disjointIPblocks []*common.IPBlock,
	origIPBlock *common.IPBlock, alignedConnectivity map[EndpointElem]map[EndpointElem]*common.ConnectionSet,
	src, dst EndpointElem, conns *common.ConnectionSet, resizeSrc bool) error {
	origBlockContainsIPBlocks := false
	for _, ipBlock := range disjointIPblocks {
		// 1. get ipBlock of resized index (src/dst)
		if !ipBlock.ContainedIn(origIPBlock) { // ipBlock not relevant here
			continue
		}
		origBlockContainsIPBlocks = true
		cidrList := ipBlock.ToCidrList()
		for _, cidr := range cidrList {
			nodeOfCidr, err := findNodeWithCidr(c.Nodes, cidr)
			if err != nil {
				return err
			}
			if resizeSrc {
				if _, ok := alignedConnectivity[nodeOfCidr]; !ok {
					alignedConnectivity[nodeOfCidr] = map[EndpointElem]*common.ConnectionSet{}
				}
				alignedConnectivity[nodeOfCidr][dst] = conns
			} else {
				alignedConnectivity[src][nodeOfCidr] = conns
			}
		}
	}
	if !origBlockContainsIPBlocks { // keep as origin
		alignedConnectivity[src][dst] = conns
	}
	return nil
}

// gets node with given cidr
func findNodeWithCidr(configNodes []Node, cidr string) (Node, error) {
	for _, node := range configNodes {
		if node.Cidr() == cidr {
			return node, nil
		}
	}
	return nil, fmt.Errorf("%s", fmt.Sprintf("A node with cidr %v not found in conf", cidr)) // should not get here
}

// get a list of IPBlocks of the src and dst of the connections
func (subnetConnectivity SubnetConnectivityMap) getIPBlocksList() (ipbList []*common.IPBlock,
	myErr error) {
	ipbList = []*common.IPBlock{}
	myErr = nil
	for src, endpointConns := range subnetConnectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}
			if src.IsExternal() {
				ipBlock, err := externalNodeToIPBlock(src.(Node))
				if err != nil {
					return nil, err
				}
				ipbList = append(ipbList, ipBlock)
			}
			if dst.IsExternal() {
				ipBlock, err := externalNodeToIPBlock(dst.(Node))
				if err != nil {
					return nil, err
				}
				ipbList = append(ipbList, ipBlock)
			}
		}
	}
	return ipbList, myErr
}

func externalNodeToIPBlock(external Node) (ipBlock *common.IPBlock, err error) {
	ipBlock, err = common.NewIPBlock(external.Cidr(), []string{})
	if err != nil {
		return nil, err
	}
	return ipBlock, err
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
////       encode the SubnetsDiff into this generic item as well as the other entities we are grouping
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
