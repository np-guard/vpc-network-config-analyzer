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
	config1 *CloudConfig
	config2 *CloudConfig
}

type SubnetConfigConnectivity struct {
	config             *CloudConfig
	subnetConnectivity SubnetConnectivityMap
}

type diffBetweenSubnets struct {
	subnet1Subtract2 SubnetsDiff
	subnet2Subtract1 SubnetsDiff

	GroupedSubnet1Minus2 *GroupConnLines
	GroupedSubnet1Minus1 *GroupConnLines
}

type ConnectionEnd struct {
	src EndpointElem
	dst EndpointElem
}

func (configs ConfigsForDiff) GetSubnetsDiff(grouping bool) (*diffBetweenSubnets, error) {
	// 1. compute connectivity for each of the subnets
	subnetsConn1, err := configs.config1.GetSubnetsConnectivity(true, false)
	if err != nil {
		return nil, nil
	}
	subnetsConn2, err := configs.config2.GetSubnetsConnectivity(true, false)
	if err != nil {
		return nil, nil
	}

	// 2. Computes delta in both directions
	subnet1Aligned, subnet2Aligned, err :=
		subnetsConn1.AllowedConnsCombined.getConnectivesWithSameIPBlocks(subnetsConn2.AllowedConnsCombined)
	if err != nil {
		return nil, err
	}
	subnetConfigConnectivity1 := SubnetConfigConnectivity{configs.config1, subnet1Aligned}
	subnetConfigConnectivity2 := SubnetConfigConnectivity{configs.config2, subnet2Aligned}
	subnet1Subtract2 := subnetConfigConnectivity1.SubnetConnectivitySubtract(&subnetConfigConnectivity2)
	subnet2Subtract1 := subnetConfigConnectivity2.SubnetConnectivitySubtract(&subnetConfigConnectivity1)

	// 3. ToDo: grouping, see comment at the end of this file

	res := &diffBetweenSubnets{
		subnet1Subtract2: subnet1Subtract2,
		subnet2Subtract1: subnet2Subtract1}
	return res, nil
}

// for a given EndpointElem (representing a subnet or an external ip) in config return the EndpointElem representing the
// subnet/external address in otherConfig or nil if the subnet does not exist in the other config.
// ToDo: this is done based on names only at the moment. Perhaps take into account other factors such as cidr?
// ToDo: instead of performing this search each time, use a map created once
func (c *CloudConfig) getEndpointElemInOtherConfig(other *CloudConfig, ep EndpointElem) EndpointElem {
	if ep.IsExternal() {
		for _, node := range other.Nodes {
			if node.Name() == ep.Name() {
				res := EndpointElem(node)
				return res
			}
		}
	} else {
		for _, nodeSet := range other.NodeSets {
			if nodeSet.Name() == ep.Name() {
				res := EndpointElem(nodeSet)
				return res
			}
		}
	}
	return nil
}

// generates from subnet1Connectivity.AllowedConnsCombined and subnet2Connectivity.AllowedConnsCombined
// Two equivalent SubnetConnectivityMap objects s.t. any (src1, dst1) of subnet1Connectivity and
// (src2, dst2) of subnet2Connectivity are either:
//  1. src1 disjoint src2 or dst1 disjoint dst2
//  2. src1 = src2 and dst1 = dst2
//     What is done here is repartitioning the ipBlocks so that the above will hold
//
// todo: verify that the returns objects indeed have exactly the same ipBlocks
func (connectivity SubnetConnectivityMap) getConnectivesWithSameIPBlocks(other SubnetConnectivityMap) (
	alignedConnectivity SubnetConnectivityMap, alignedOther SubnetConnectivityMap, err error) {

	// Resize connectivity and other s.t. all detected connections are resized to meet 1 and 2 above
	// To that end we get a list of all disjoint src IPBlocks and dst IPBlocks
	// and resize by the disjoint IPBlocks
	// todo: use DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock  of ipBlock.go
	alignedConnectivity = connectivity
	alignedOther = other
	return
}

// todo: write a function that for SubnetConnectivityMap and a src/dst returns a list of *ipBlocks
//func ()

// SubnetConnectivitySubtract Subtract one SubnetConnectivityMap from the other
// assumption: any connection from connectivity and "other" have src (dst) which are either disjoint or equal
func (subnetConfConnectivity *SubnetConfigConnectivity) SubnetConnectivitySubtract(other *SubnetConfigConnectivity) SubnetsDiff {
	connectivitySubtract := map[EndpointElem]map[EndpointElem]*connectionDiff{}
	for src, endpointConns := range subnetConfConnectivity.subnetConnectivity {
		for dst, conns := range endpointConns {
			if src.IsExternal() || dst.IsExternal() { // todo: tmp
				continue
			}
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
						// ToDo: current missing stateful:
						// todo 1. is the delta connection stateful
						// todo 2. connectionProperties is identical but conn stateful while other is not
						//     the 2nd item can be computed by conns.Subtract, with enhancement to relevant structure
						//     the 1st can not since we do not know where exactly the statefullness came from
						//     we might need to repeat the statefullness computation for the delta connection
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

// todo: the following code finds all couples of connections that should be resized (it IPBlock)
//
//		it seems that the code is redundant; yet we keep it with its unit test in case we'll decide
//		to use it in the future
//	 it return a string describing the intersecting connections for the unit test
func (connectivity SubnetConnectivityMap) getIntersectingConnections(other SubnetConnectivityMap) (areIntersecting string,
	err error) {
	err = nil
	for src, endpointConns := range connectivity {
		for dst, conns := range endpointConns {
			if (!src.IsExternal() && !dst.IsExternal()) || conns.IsEmpty() {
				continue // nothing to do here
			}
			for otherSrc, otherEndpointConns := range other {
				for otherDst, otherConns := range otherEndpointConns {
					if otherConns.IsEmpty() {
						continue
					}
					bothSrcExt := src.IsExternal() && otherSrc.IsExternal()
					bothDstExt := dst.IsExternal() && otherDst.IsExternal()
					if (!bothSrcExt && !bothDstExt) ||
						otherConns.IsEmpty() {
						continue // nothing to compare to here
					}
					myEp := &ConnectionEnd{src, dst}
					otherEp := &ConnectionEnd{otherSrc, otherDst}
					intersecting, err := myEp.connectionsIntersecting(otherEp)
					if err != nil {
						return areIntersecting, err
					}
					if intersecting {
						areIntersecting += fmt.Sprintf("<%v, %v> and <%v, %v> intersects\n", src.Name(), dst.Name(), otherSrc.Name(), otherDst.Name())
					}
				}
			}
		}
	}
	return areIntersecting, err
}

// two connections s.t. each contains at least one external end are comparable if either:
// both src and dst in both connections are external and they both intersect
// one end (src/dst) are external in both and intersects and the other (dst/src) are the same subnet
// two connections s.t. each contains at least one external end are comparable if either:
// both src and dst in both connections are external and they both intersect but not equal
// or end (src/dst) are external in both and intersects and the other (dst/src) are the same subnet
func (myConnEnd *ConnectionEnd) connectionsIntersecting(otherConnEnd *ConnectionEnd) (bool, error) {
	srcComparable, err := pairEpsComparable(myConnEnd.src, otherConnEnd.src)
	if err != nil {
		return false, err
	}
	if !srcComparable {
		return false, nil
	}
	dstComparable, err := pairEpsComparable(myConnEnd.dst, otherConnEnd.dst)
	if err != nil {
		return false, err
	}
	if !dstComparable {
		return false, err
	}
	return true, nil
}

// checks if two eps refers to the same subnet or
// refers to intersecting external addresses
func pairEpsComparable(myEp, otherEp EndpointElem) (bool, error) {
	mySubnet, isMySubnet := myEp.(NodeSet)
	otherSubnet, isOtherSubnet := otherEp.(NodeSet)
	myExternal, isMyExternal := myEp.(Node)
	otherExternal, isOtherExternal := otherEp.(Node)
	if (isMySubnet != isOtherSubnet) || (isMyExternal != isOtherExternal) {
		return false, nil
	}
	if isMySubnet { // implies that isOtherSubnet as well
		if mySubnet.Name() == otherSubnet.Name() {
			return true, nil
		} else {
			return false, nil
		}
	}
	// if we got here then both eps refer to external IP
	myIpBlock, err := common.NewIPBlock(myExternal.Cidr(), []string{})
	if err != nil {
		return false, err
	}
	otherIpBlock, err := common.NewIPBlock(otherExternal.Cidr(), []string{})
	if err != nil {
		return false, err
	}
	// we need to resize if the IpBlocks are intersecting but not equal
	//fmt.Printf("\t<%v, %v>: cidrs: %v, %v\n", myEp.Name(), otherEp.Name(), myExternal.Cidr(), otherExternal.Cidr())
	if !myIpBlock.Equal(otherIpBlock) && !myIpBlock.Intersection(otherIpBlock).Empty() {
		return true, nil
	}
	return false, nil
}

// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
//       encode the SubnetsDiff into this generic item as well as the other entities we are grouping
//       and then decode in the printing
//       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
//       and also the diff where relevant
//       this will requires some rewriting in the existing grouping functionality and the way it provides
//       service to subnetsConnectivity and nodesConnectivity
