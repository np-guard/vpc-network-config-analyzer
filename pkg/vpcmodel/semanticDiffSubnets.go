package vpcmodel

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// ToDo: go over structs specifically * and lack of

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
	DiffType
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

type DiffType = int

func (configs ConfigsForDiff) GetSubnetsDiff(grouping bool) (*diffBetweenSubnets, error) {
	// 1. compute connectivity for each of the subnets
	subnetsConn1, err := configs.config1.GetSubnetsConnectivity(true, grouping)
	if err != nil {
		return nil, nil
	}
	subnetsConn2, err := configs.config2.GetSubnetsConnectivity(true, grouping)
	if err != nil {
		return nil, nil
	}

	// 2. Computes delta in both directions
	subnet1Aligned, subnet2Aligned := subnetsConn1.AllowedConnsCombined.getConnectivesWithSameIpBlocks(subnetsConn2.AllowedConnsCombined)
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
func (config *CloudConfig) getEndpointElemInOtherConfig(other *CloudConfig, ep EndpointElem) *EndpointElem {
	if ep.IsExternal() {
		for _, node := range other.Nodes {
			if node.Name() == ep.Name() {
				res := EndpointElem(node)
				return &res
			}
		}
	} else {
		for _, nodeSet := range other.NodeSets {
			if nodeSet.Name() == ep.Name() {
				res := EndpointElem(nodeSet)
				return &res
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
func (connectivity SubnetConnectivityMap) getConnectivesWithSameIpBlocks(other SubnetConnectivityMap) (SubnetConnectivityMap, SubnetConnectivityMap) {
	// todo: use DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock  of ipBlock.go
	return connectivity, other
}

// Subtract one SubnetConnectivityMap from the other
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
			srcInOther := subnetConfConnectivity.config.getEndpointElemInOtherConfig(other.config, src)
			dstInOther := subnetConfConnectivity.config.getEndpointElemInOtherConfig(other.config, dst)
			if srcInOther != nil && dstInOther != nil {
				if otherSrc, ok := other.subnetConnectivity[*srcInOther]; ok {
					if otherSrcDst, ok := otherSrc[*dstInOther]; ok {
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
						diffConnectionWithType := &connectionDiff{
							subtractConn,
							ChangedConnection,
						}
						connectivitySubtract[src][dst] = diffConnectionWithType
						continue
					}
				}
			}
			var diff DiffType
			if srcInOther == nil && dstInOther == nil {
				diff = MissingSrcDstEP
			} else if srcInOther == nil {
				diff = MissingSrcEP
			} else {
				diff = MissingDstEP
			}
			diffConnectionWithType := &connectionDiff{
				nil,
				diff,
			}
			connectivitySubtract[src][dst] = diffConnectionWithType
		}
	}
	return connectivitySubtract
}

// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
//       encode the SubnetsDiff into this generic item as well as the other entities we are grouping
//       and then decode in the printing
//       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
//       and also the diff where relevant
//       this will requires some rewriting in the existing grouping functionality and the way it provides service to subnetsConnectivity and nodesConnectivity
