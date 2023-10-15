package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

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
	common.ConnectionSetDiff
	DiffType
}

type SubnetsDiff map[EndpointElem]map[EndpointElem]*connectionDiff

type configsForDiff struct {
	config1 *CloudConfig
	config2 *CloudConfig
}

type diffBetweenSubnets struct {
	subnet1Subtract2 SubnetsDiff
	subnet2Subtract1 SubnetsDiff

	GroupedSubnet1Minus2 *GroupConnLines
	GroupedSubnet1Minus1 *GroupConnLines
}

type DiffType = int

func (configs configsForDiff) GetSubnetsDiff(grouping bool) (*diffBetweenSubnets, error) {
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
	subnet1Subtract2 := configs.subnetConnectivitySubtract(subnet1Aligned, subnet2Aligned)
	subnet2Subtract1 := configs.subnetConnectivitySubtract(subnet2Aligned, subnet1Aligned)

	// 3. ToDo: grouping, see comment at the end of this file

	res := &diffBetweenSubnets{subnet1Subtract2: subnet1Subtract2,
		subnet2Subtract1: subnet2Subtract1}
	return res, nil
}

// generates from subnet1Connectivity.AllowedConnsCombined and subnet2Connectivity.AllowedConnsCombined
// Two equivalent subnetConnectivity objects s.t. any (src1, dst1) of subnet1Connectivity and
// (src2, dst2) of subnet2Connectivity are either:
//  1. src1 disjoint src2 or dst1 disjoint dst2
//  2. src1 = src2 and dst1 = dst2
func (connectivity subnetConnectivity) getConnectivesWithSameIpBlocks(other subnetConnectivity) (subnetConnectivity, subnetConnectivity) {
	// todo: use DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock  of ipBlock.go
	return connectivity, other
}

// assumption: any connection from connectivity and "other" have src (dst) which are either disjoint or equal
func (configs configsForDiff) subnetConnectivitySubtract(connectivity subnetConnectivity, other subnetConnectivity) SubnetsDiff {
	connectivitySubtract := map[EndpointElem]map[EndpointElem]*connectionDiff{}
	for src, endpointConns := range connectivity {
		for dst, conns := range endpointConns {
			if conns.IsEmpty() {
				continue
			}

			if _, ok := connectivitySubtract[src]; !ok {
				connectivitySubtract[src] = map[EndpointElem]*connectionDiff{}
			}
			if otherSrc, existSrc := other[src]; existSrc {
				if otherSrcDst, existDst := otherSrc[dst]; existDst {
					diffConnection := conns.Subtract(otherSrcDst)
					if diffConnection.IsEmpty() {
						continue // no diff
					}
					connectionSetDiff := common.ConnectionSetDiff{
						*diffConnection,
						nil,
					}
					diffConnectionWithType := &connectionDiff{
						connectionSetDiff,
						ChangedConnection,
					}
					connectivitySubtract[src][dst] = diffConnectionWithType
				}
				// todo: if src, dst do not exist as node see if src missing in config, dst missing or both missing
				// todo: if src and dst both present then call ConnectionSet1Minus2
			}
		}
	}

	return nil
}

// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
//       encode the SubnetsDiff into this generic item as well as the other entities we are grouping
//       and then decode in the printing
//       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
//       and also the diff where relevant
//       this will requires some rewriting in the existing grouping functionality and the way it provides service to subnetsConnectivity and nodesConnectivity
