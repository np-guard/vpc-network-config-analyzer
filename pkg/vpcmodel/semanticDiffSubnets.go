package vpcmodel

import "github.com/np-guard/vpc-network-config-analyzer/pkg/common"

type SubnetsDiff map[EndpointElem]map[EndpointElem]*common.ConnectionSetDiff

type diffBetweenSubnets struct {
	subnet1Connectivity VPCsubnetConnectivity
	subnet2Connectivity VPCsubnetConnectivity
	subnet1Minus2       SubnetsDiff
	subnet2Minus1       SubnetsDiff

	GroupedSubnet1Minus2 *GroupConnLines
	GroupedSubnet1Minus1 *GroupConnLines
}

type DiffType = int

const (
	NoDiff DiffType = iota
	MissingSrcEP
	MissingDstEP
	MissingSrcDstEP
	MissingConnection
	ChangedConnection
)

func (c *CloudConfig) GetSubnetsDiff(grouping bool) (*diffBetweenSubnets, error) {
	return nil, nil
}

// generates from subnet1Connectivity.AllowedConnsCombined and subnet2Connectivity.AllowedConnsCombined
// Two equivalent subnetConnectivity objects s.t. any (src1, dst1) of subnet1Connectivity and
// (src2, dst2) of subnet2Connectivity are either:
//  1. src1 disjoint src2 or dst1 disjoint dst2
//  2. src1 = src2 and dst1 = dst2
//
// todo: use DisjointIPBlocks(set1, set2 []*IPBlock) []*IPBlock  of ipBlock.go
func (d *diffBetweenSubnets) getConnectivesWithSameIpBlocks() (*subnetConnectivity, *subnetConnectivity) {
	return nil, nil
}

func (connectivity *subnetConnectivity) subnetConnectivitySubtract(other subnetConnectivity) DiffType {

	return NoDiff
}

// todo: instead of adding functionality to grouping, I plan to have more generic connectivity items that will be grouped
//       encode the SubnetsDiff into this generic item as well as the other entities we are grouping
//       and then decode in the printing
//       the idea is to use instead of *common.ConnectionSet in the grouped entity a string which will encode the connection
//       and also the diff where relevant
//       this will requires some rewriting in the existing grouping functionality and the way it provides service to subnetsConnectivity and nodesConnectivity
